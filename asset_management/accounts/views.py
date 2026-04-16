from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q

from .models import Role, UserProfile
from .forms import LoginForm, UserCreateForm, UserUpdateForm, UserProfileForm, RoleForm
from assets.models import ActivityLog


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


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            log_activity(user, 'login', 'User', user, request=request)
            messages.success(request, f'Welcome back, {user.get_full_name() or user.username}!')
            return redirect(request.GET.get('next', 'dashboard'))
        else:
            messages.error(request, 'Invalid username or password.')
    else:
        form = LoginForm()
    return render(request, 'accounts/login.html', {'form': form})


@login_required
def logout_view(request):
    log_activity(request.user, 'logout', 'User', request.user, request=request)
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('login')


@login_required
@permission_required('can_manage_users')
def user_list(request):
    users = User.objects.select_related('profile', 'profile__role').order_by('username')
    search = request.GET.get('search', '')
    if search:
        users = users.filter(
            Q(username__icontains=search) |
            Q(first_name__icontains=search) |
            Q(last_name__icontains=search) |
            Q(email__icontains=search)
        )
    paginator = Paginator(users, 25)
    page = request.GET.get('page')
    users_page = paginator.get_page(page)
    return render(request, 'accounts/user_list.html', {'users': users_page, 'search': search})


@login_required
@permission_required('can_manage_users')
def user_create(request):
    if request.method == 'POST':
        user_form = UserCreateForm(request.POST)
        profile_form = UserProfileForm(request.POST, request.FILES)
        if user_form.is_valid() and profile_form.is_valid():
            user = user_form.save()
            profile = profile_form.save(commit=False)
            profile.user = user
            profile.save()
            log_activity(request.user, 'create', 'User', user, request=request)
            messages.success(request, f'User "{user.username}" created successfully.')
            return redirect('user_list')
    else:
        user_form = UserCreateForm()
        profile_form = UserProfileForm()
    return render(request, 'accounts/user_form.html', {
        'user_form': user_form,
        'profile_form': profile_form,
        'title': 'Create User',
    })


@login_required
@permission_required('can_manage_users')
def user_edit(request, pk):
    user_obj = get_object_or_404(User, pk=pk)
    profile, _ = UserProfile.objects.get_or_create(user=user_obj)
    if request.method == 'POST':
        user_form = UserUpdateForm(request.POST, instance=user_obj)
        profile_form = UserProfileForm(request.POST, request.FILES, instance=profile)
        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            log_activity(request.user, 'update', 'User', user_obj, request=request)
            messages.success(request, f'User "{user_obj.username}" updated successfully.')
            return redirect('user_list')
    else:
        user_form = UserUpdateForm(instance=user_obj)
        profile_form = UserProfileForm(instance=profile)
    return render(request, 'accounts/user_form.html', {
        'user_form': user_form,
        'profile_form': profile_form,
        'user_obj': user_obj,
        'title': 'Edit User',
    })


@login_required
@permission_required('can_manage_users')
def user_delete(request, pk):
    user_obj = get_object_or_404(User, pk=pk)
    if user_obj == request.user:
        messages.error(request, 'You cannot delete your own account.')
        return redirect('user_list')
    if request.method == 'POST':
        name = user_obj.username
        log_activity(request.user, 'delete', 'User', user_obj, request=request)
        user_obj.delete()
        messages.success(request, f'User "{name}" deleted.')
        return redirect('user_list')
    return render(request, 'accounts/user_confirm_delete.html', {'user_obj': user_obj})


@login_required
@permission_required('can_manage_roles')
def role_list(request):
    roles = Role.objects.all()
    return render(request, 'accounts/role_list.html', {'roles': roles})


@login_required
@permission_required('can_manage_roles')
def role_create(request):
    if request.method == 'POST':
        form = RoleForm(request.POST)
        if form.is_valid():
            role = form.save()
            log_activity(request.user, 'create', 'Role', role, request=request)
            messages.success(request, f'Role "{role.name}" created.')
            return redirect('role_list')
    else:
        form = RoleForm()
    return render(request, 'accounts/role_form.html', {'form': form, 'title': 'Create Role'})


@login_required
@permission_required('can_manage_roles')
def role_edit(request, pk):
    role = get_object_or_404(Role, pk=pk)
    if request.method == 'POST':
        form = RoleForm(request.POST, instance=role)
        if form.is_valid():
            role = form.save()
            log_activity(request.user, 'update', 'Role', role, request=request)
            messages.success(request, f'Role "{role.name}" updated.')
            return redirect('role_list')
    else:
        form = RoleForm(instance=role)
    return render(request, 'accounts/role_form.html', {'form': form, 'role': role, 'title': 'Edit Role'})


@login_required
@permission_required('can_manage_roles')
def role_delete(request, pk):
    role = get_object_or_404(Role, pk=pk)
    if request.method == 'POST':
        name = role.name
        log_activity(request.user, 'delete', 'Role', role, request=request)
        role.delete()
        messages.success(request, f'Role "{name}" deleted.')
        return redirect('role_list')
    return render(request, 'accounts/role_confirm_delete.html', {'role': role})


@login_required
def profile_view(request):
    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    if request.method == 'POST':
        user_form = UserUpdateForm(request.POST, instance=request.user)
        profile_form = UserProfileForm(request.POST, request.FILES, instance=profile)
        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            messages.success(request, 'Profile updated successfully.')
            return redirect('profile')
    else:
        user_form = UserUpdateForm(instance=request.user)
        profile_form = UserProfileForm(instance=profile)
    return render(request, 'accounts/profile.html', {
        'user_form': user_form,
        'profile_form': profile_form,
    })
