from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse
from django.db.models import Q, Count
from django.core.paginator import Paginator
from datetime import date
import tablib

from .models import Asset, Category, Location, Department, AssetIncident, AssetUpgrade, ActivityLog
from .forms import (
    AssetForm, CategoryForm, LocationForm, DepartmentForm,
    AssetIncidentForm, AssetUpgradeForm, ImportForm, AssetFilterForm
)
from .resources import AssetResource, CategoryResource, LocationResource, DepartmentResource


def log_activity(user, action, model_name, obj=None, changes='', request=None):
    ip = None
    if request:
        x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
        ip = x_forwarded.split(',')[0] if x_forwarded else request.META.get('REMOTE_ADDR')
    ActivityLog.objects.create(
        user=user,
        action=action,
        model_name=model_name,
        object_id=str(obj.pk) if obj else '',
        object_repr=str(obj) if obj else '',
        changes=changes,
        ip_address=ip,
    )


def permission_required(perm):
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                from django.contrib.auth.views import redirect_to_login
                return redirect_to_login(request.get_full_path())
            if request.user.is_superuser:
                return view_func(request, *args, **kwargs)
            try:
                profile = request.user.profile
                if not profile.has_permission(perm):
                    messages.error(request, 'You do not have permission to perform this action.')
                    return redirect('dashboard')
            except Exception:
                messages.error(request, 'You do not have permission to perform this action.')
                return redirect('dashboard')
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


@login_required
def dashboard(request):
    total_assets = Asset.objects.count()
    working_assets = Asset.objects.filter(condition='working').count()
    condemned_assets = Asset.objects.filter(condition='condemned').count()
    disposed_assets = Asset.objects.filter(condition='disposed').count()
    write_off_assets = Asset.objects.filter(condition='write_off').count()
    obsolete_assets = Asset.objects.filter(condition='obsolete').count()

    warranty_expired = 0
    warranty_expiring_soon = 0
    for asset in Asset.objects.filter(warranty_years__gt=0, date_of_purchase__isnull=False):
        ws = asset.warranty_status
        if ws == 'Expired':
            warranty_expired += 1
        elif ws == 'Expiring Soon':
            warranty_expiring_soon += 1

    assets_by_category = Category.objects.annotate(count=Count('assets')).order_by('-count')[:8]
    assets_by_location = Location.objects.annotate(count=Count('assets')).order_by('-count')[:8]
    assets_by_department = Department.objects.annotate(count=Count('assets')).order_by('-count')[:8]
    assets_by_condition = list(Asset.objects.values('condition').annotate(count=Count('condition')))
    assets_by_status = list(Asset.objects.values('working_status').annotate(count=Count('working_status')))

    recent_assets = Asset.objects.select_related('category', 'location', 'department').order_by('-created_at')[:10]
    recent_logs = ActivityLog.objects.select_related('user').order_by('-timestamp')[:10]

    context = {
        'total_assets': total_assets,
        'working_assets': working_assets,
        'condemned_assets': condemned_assets,
        'disposed_assets': disposed_assets,
        'write_off_assets': write_off_assets,
        'obsolete_assets': obsolete_assets,
        'warranty_expired': warranty_expired,
        'warranty_expiring_soon': warranty_expiring_soon,
        'total_categories': Category.objects.count(),
        'total_locations': Location.objects.count(),
        'total_departments': Department.objects.count(),
        'assets_by_category': assets_by_category,
        'assets_by_location': assets_by_location,
        'assets_by_department': assets_by_department,
        'assets_by_condition': assets_by_condition,
        'assets_by_status': assets_by_status,
        'recent_assets': recent_assets,
        'recent_logs': recent_logs,
    }
    return render(request, 'assets/dashboard.html', context)


@login_required
@permission_required('can_view_asset')
def asset_list(request):
    form = AssetFilterForm(request.GET)
    assets = Asset.objects.select_related('category', 'location', 'department').all()

    if form.is_valid():
        search = form.cleaned_data.get('search')
        category = form.cleaned_data.get('category')
        location = form.cleaned_data.get('location')
        department = form.cleaned_data.get('department')
        condition = form.cleaned_data.get('condition')
        working_status = form.cleaned_data.get('working_status')

        if search:
            assets = assets.filter(
                Q(inventory_number__icontains=search) |
                Q(inventory_name__icontains=search) |
                Q(serial_number__icontains=search) |
                Q(assigned_to__icontains=search) |
                Q(make__icontains=search) |
                Q(model__icontains=search)
            )
        if category:
            assets = assets.filter(category=category)
        if location:
            assets = assets.filter(location=location)
        if department:
            assets = assets.filter(department=department)
        if condition:
            assets = assets.filter(condition=condition)
        if working_status:
            assets = assets.filter(working_status=working_status)

    paginator = Paginator(assets, 25)
    page = request.GET.get('page')
    assets_page = paginator.get_page(page)

    return render(request, 'assets/asset_list.html', {
        'assets': assets_page,
        'form': form,
        'total_count': assets.count(),
    })


@login_required
@permission_required('can_view_asset')
def asset_detail(request, pk):
    asset = get_object_or_404(Asset, pk=pk)
    incidents = asset.incidents.all().order_by('-reported_at')
    upgrades = asset.upgrades.all().order_by('-upgrade_date')
    log_activity(request.user, 'view', 'Asset', asset, request=request)
    return render(request, 'assets/asset_detail.html', {
        'asset': asset,
        'incidents': incidents,
        'upgrades': upgrades,
    })


@login_required
@permission_required('can_add_asset')
def asset_create(request):
    if request.method == 'POST':
        form = AssetForm(request.POST, request.FILES)
        if form.is_valid():
            asset = form.save(commit=False)
            asset.created_by = request.user
            asset.updated_by = request.user
            asset.save()
            log_activity(request.user, 'create', 'Asset', asset, request=request)
            messages.success(request, f'Asset "{asset.inventory_name}" created successfully.')
            return redirect('asset_detail', pk=asset.pk)
    else:
        form = AssetForm()
    return render(request, 'assets/asset_form.html', {'form': form, 'title': 'Add New Asset'})


@login_required
@permission_required('can_edit_asset')
def asset_edit(request, pk):
    asset = get_object_or_404(Asset, pk=pk)
    if request.method == 'POST':
        form = AssetForm(request.POST, request.FILES, instance=asset)
        if form.is_valid():
            asset = form.save(commit=False)
            asset.updated_by = request.user
            asset.save()
            log_activity(request.user, 'update', 'Asset', asset, request=request)
            messages.success(request, f'Asset "{asset.inventory_name}" updated successfully.')
            return redirect('asset_detail', pk=asset.pk)
    else:
        form = AssetForm(instance=asset)
    return render(request, 'assets/asset_form.html', {'form': form, 'asset': asset, 'title': 'Edit Asset'})


@login_required
@permission_required('can_delete_asset')
def asset_delete(request, pk):
    asset = get_object_or_404(Asset, pk=pk)
    if request.method == 'POST':
        name = str(asset)
        log_activity(request.user, 'delete', 'Asset', asset, request=request)
        asset.delete()
        messages.success(request, f'Asset "{name}" deleted successfully.')
        return redirect('asset_list')
    return render(request, 'assets/asset_confirm_delete.html', {'asset': asset})


@login_required
@permission_required('can_edit_asset')
def add_incident(request, pk):
    asset = get_object_or_404(Asset, pk=pk)
    if request.method == 'POST':
        form = AssetIncidentForm(request.POST)
        if form.is_valid():
            incident = form.save(commit=False)
            incident.asset = asset
            incident.reported_by = request.user
            incident.save()
            log_activity(request.user, 'create', 'AssetIncident', incident, request=request)
            messages.success(request, 'Incident reported successfully.')
            return redirect('asset_detail', pk=pk)
    else:
        form = AssetIncidentForm()
    return render(request, 'assets/incident_form.html', {'form': form, 'asset': asset})


@login_required
@permission_required('can_edit_asset')
def add_upgrade(request, pk):
    asset = get_object_or_404(Asset, pk=pk)
    if request.method == 'POST':
        form = AssetUpgradeForm(request.POST)
        if form.is_valid():
            upgrade = form.save(commit=False)
            upgrade.asset = asset
            upgrade.recorded_by = request.user
            upgrade.save()
            log_activity(request.user, 'create', 'AssetUpgrade', upgrade, request=request)
            messages.success(request, 'Upgrade recorded successfully.')
            return redirect('asset_detail', pk=pk)
    else:
        form = AssetUpgradeForm()
    return render(request, 'assets/upgrade_form.html', {'form': form, 'asset': asset})


@login_required
@permission_required('can_import_export')
def import_assets(request):
    if request.method == 'POST':
        form = ImportForm(request.POST, request.FILES)
        if form.is_valid():
            import_type = form.cleaned_data['import_type']
            file = form.cleaned_data['file']
            resource_map = {
                'assets': AssetResource,
                'categories': CategoryResource,
                'locations': LocationResource,
                'departments': DepartmentResource,
            }
            resource_class = resource_map.get(import_type)
            if resource_class:
                resource = resource_class()
                ext = file.name.split('.')[-1].lower()
                content = file.read()
                try:
                    if ext == 'csv':
                        dataset = tablib.Dataset().load(content.decode('utf-8'), headers=True)
                    else:
                        dataset = tablib.Dataset().load(content, headers=True)
                    result = resource.import_data(dataset, dry_run=True)
                    if not result.has_errors():
                        resource.import_data(dataset, dry_run=False)
                        log_activity(request.user, 'import', import_type.capitalize(), changes=f'Imported {dataset.height} records', request=request)
                        messages.success(request, f'Successfully imported {dataset.height} {import_type}.')
                    else:
                        messages.error(request, 'Import failed. Please check your file format and data.')
                except Exception as e:
                    messages.error(request, f'Import error: {str(e)}')
        return redirect('import_assets')
    else:
        form = ImportForm()
    return render(request, 'assets/import.html', {'form': form})


@login_required
@permission_required('can_import_export')
def export_assets(request):
    export_type = request.GET.get('type', 'assets')
    fmt = request.GET.get('format', 'xlsx')
    resource_map = {
        'assets': (AssetResource, 'assets'),
        'categories': (CategoryResource, 'categories'),
        'locations': (LocationResource, 'locations'),
        'departments': (DepartmentResource, 'departments'),
    }
    resource_class, label = resource_map.get(export_type, (AssetResource, 'assets'))
    resource = resource_class()
    dataset = resource.export()
    log_activity(request.user, 'export', label.capitalize(), changes=f'Exported {len(dataset)} records', request=request)
    if fmt == 'csv':
        response = HttpResponse(dataset.csv, content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="{label}.csv"'
    else:
        response = HttpResponse(dataset.xlsx, content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = f'attachment; filename="{label}.xlsx"'
    return response


@login_required
def category_list(request):
    categories = Category.objects.annotate(asset_count=Count('assets')).order_by('name')
    return render(request, 'assets/category_list.html', {'categories': categories})


@login_required
def category_create(request):
    if request.method == 'POST':
        form = CategoryForm(request.POST)
        if form.is_valid():
            category = form.save()
            log_activity(request.user, 'create', 'Category', category, request=request)
            messages.success(request, f'Category "{category.name}" created.')
            return redirect('category_list')
    else:
        form = CategoryForm()
    return render(request, 'assets/category_form.html', {'form': form, 'title': 'Add Category'})


@login_required
def category_edit(request, pk):
    category = get_object_or_404(Category, pk=pk)
    if request.method == 'POST':
        form = CategoryForm(request.POST, instance=category)
        if form.is_valid():
            category = form.save()
            log_activity(request.user, 'update', 'Category', category, request=request)
            messages.success(request, f'Category "{category.name}" updated.')
            return redirect('category_list')
    else:
        form = CategoryForm(instance=category)
    return render(request, 'assets/category_form.html', {'form': form, 'category': category, 'title': 'Edit Category'})


@login_required
def category_delete(request, pk):
    category = get_object_or_404(Category, pk=pk)
    if request.method == 'POST':
        name = category.name
        log_activity(request.user, 'delete', 'Category', category, request=request)
        category.delete()
        messages.success(request, f'Category "{name}" deleted.')
        return redirect('category_list')
    return render(request, 'assets/confirm_delete.html', {'object': category, 'type': 'Category'})


@login_required
def location_list(request):
    locations = Location.objects.annotate(asset_count=Count('assets')).order_by('name')
    return render(request, 'assets/location_list.html', {'locations': locations})


@login_required
def location_create(request):
    if request.method == 'POST':
        form = LocationForm(request.POST)
        if form.is_valid():
            location = form.save()
            log_activity(request.user, 'create', 'Location', location, request=request)
            messages.success(request, f'Location "{location.name}" created.')
            return redirect('location_list')
    else:
        form = LocationForm()
    return render(request, 'assets/location_form.html', {'form': form, 'title': 'Add Location'})


@login_required
def location_edit(request, pk):
    location = get_object_or_404(Location, pk=pk)
    if request.method == 'POST':
        form = LocationForm(request.POST, instance=location)
        if form.is_valid():
            location = form.save()
            log_activity(request.user, 'update', 'Location', location, request=request)
            messages.success(request, f'Location "{location.name}" updated.')
            return redirect('location_list')
    else:
        form = LocationForm(instance=location)
    return render(request, 'assets/location_form.html', {'form': form, 'location': location, 'title': 'Edit Location'})


@login_required
def location_delete(request, pk):
    location = get_object_or_404(Location, pk=pk)
    if request.method == 'POST':
        name = str(location)
        log_activity(request.user, 'delete', 'Location', location, request=request)
        location.delete()
        messages.success(request, f'Location "{name}" deleted.')
        return redirect('location_list')
    return render(request, 'assets/confirm_delete.html', {'object': location, 'type': 'Location'})


@login_required
def department_list(request):
    departments = Department.objects.annotate(asset_count=Count('assets')).order_by('name')
    return render(request, 'assets/department_list.html', {'departments': departments})


@login_required
def department_create(request):
    if request.method == 'POST':
        form = DepartmentForm(request.POST)
        if form.is_valid():
            dept = form.save()
            log_activity(request.user, 'create', 'Department', dept, request=request)
            messages.success(request, f'Department "{dept.name}" created.')
            return redirect('department_list')
    else:
        form = DepartmentForm()
    return render(request, 'assets/department_form.html', {'form': form, 'title': 'Add Department'})


@login_required
def department_edit(request, pk):
    dept = get_object_or_404(Department, pk=pk)
    if request.method == 'POST':
        form = DepartmentForm(request.POST, instance=dept)
        if form.is_valid():
            dept = form.save()
            log_activity(request.user, 'update', 'Department', dept, request=request)
            messages.success(request, f'Department "{dept.name}" updated.')
            return redirect('department_list')
    else:
        form = DepartmentForm(instance=dept)
    return render(request, 'assets/department_form.html', {'form': form, 'dept': dept, 'title': 'Edit Department'})


@login_required
def department_delete(request, pk):
    dept = get_object_or_404(Department, pk=pk)
    if request.method == 'POST':
        name = dept.name
        log_activity(request.user, 'delete', 'Department', dept, request=request)
        dept.delete()
        messages.success(request, f'Department "{name}" deleted.')
        return redirect('department_list')
    return render(request, 'assets/confirm_delete.html', {'object': dept, 'type': 'Department'})


@login_required
@permission_required('can_view_logs')
def activity_log_list(request):
    logs = ActivityLog.objects.select_related('user').all()
    search = request.GET.get('search', '')
    action = request.GET.get('action', '')
    model = request.GET.get('model', '')
    if search:
        logs = logs.filter(Q(user__username__icontains=search) | Q(object_repr__icontains=search))
    if action:
        logs = logs.filter(action=action)
    if model:
        logs = logs.filter(model_name__icontains=model)
    paginator = Paginator(logs, 50)
    page = request.GET.get('page')
    logs_page = paginator.get_page(page)
    return render(request, 'assets/activity_log.html', {
        'logs': logs_page,
        'action_choices': ActivityLog.ACTION_CHOICES,
    })
