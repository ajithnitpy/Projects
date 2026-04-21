from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import FileResponse, Http404
from django.db.models import Q
from .models import FileRepository, SharedFile
from .forms import FileRepositoryForm, SharedFileUploadForm


def _can(user, action):
    if user.is_superuser:
        return True
    profile = getattr(user, 'profile', None)
    if not profile:
        return False
    perm_map = {
        'upload': 'can_upload_file',
        'delete': 'can_delete_file',
        'manage_repo': 'can_create_repo',
    }
    return profile.has_permission(perm_map.get(action, ''))


def file_landing(request):
    open_repos = FileRepository.objects.filter(access_type='open').prefetch_related('files')
    recent_files = SharedFile.objects.filter(
        repository__access_type='open'
    ).select_related('repository', 'uploaded_by').order_by('-created_at')[:12]
    return render(request, 'files/landing.html', {
        'open_repos': open_repos,
        'recent_files': recent_files,
    })


@login_required
def file_dashboard(request):
    all_repos = FileRepository.objects.select_related('location', 'department', 'created_by')
    accessible = [r for r in all_repos if r.is_accessible_by(request.user)]
    open_count = sum(1 for r in accessible if r.access_type == 'open')
    lab_count = sum(1 for r in accessible if r.access_type == 'lab')
    restricted_count = sum(1 for r in accessible if r.access_type == 'restricted')
    total_files = SharedFile.objects.filter(repository__in=accessible).count()
    recent_files = SharedFile.objects.filter(
        repository__in=accessible
    ).select_related('repository', 'uploaded_by').order_by('-created_at')[:8]
    return render(request, 'files/dashboard.html', {
        'accessible_repos': accessible,
        'open_count': open_count,
        'lab_count': lab_count,
        'restricted_count': restricted_count,
        'total_files': total_files,
        'recent_files': recent_files,
        'can_upload': _can(request.user, 'upload'),
        'can_manage_repo': _can(request.user, 'manage_repo'),
    })


@login_required
def repository_list(request):
    all_repos = FileRepository.objects.select_related('location', 'department', 'created_by')
    accessible = [r for r in all_repos if r.is_accessible_by(request.user)]
    return render(request, 'files/repository_list.html', {
        'repositories': accessible,
        'can_manage_repo': _can(request.user, 'manage_repo'),
    })


@login_required
def file_list(request, repo_pk):
    repo = get_object_or_404(FileRepository, pk=repo_pk)
    if not repo.is_accessible_by(request.user):
        messages.error(request, "You don't have access to this repository.")
        return redirect('file_dashboard')
    files = repo.files.select_related('uploaded_by').order_by('-created_at')
    search = request.GET.get('q', '').strip()
    if search:
        files = files.filter(
            Q(title__icontains=search) | Q(description__icontains=search) | Q(file_name__icontains=search)
        )
    return render(request, 'files/file_list.html', {
        'repo': repo,
        'files': files,
        'search': search,
        'can_upload': _can(request.user, 'upload'),
        'can_delete': _can(request.user, 'delete'),
        'can_manage_repo': _can(request.user, 'manage_repo'),
    })


@login_required
def file_upload(request, repo_pk):
    repo = get_object_or_404(FileRepository, pk=repo_pk)
    if not repo.is_accessible_by(request.user):
        messages.error(request, "You don't have access to this repository.")
        return redirect('file_dashboard')
    if not _can(request.user, 'upload'):
        messages.error(request, "You don't have permission to upload files.")
        return redirect('file_list', repo_pk=repo_pk)
    if request.method == 'POST':
        form = SharedFileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            shared_file = form.save(commit=False)
            shared_file.repository = repo
            shared_file.uploaded_by = request.user
            uploaded = request.FILES['file']
            shared_file.file_name = uploaded.name
            shared_file.file_size = uploaded.size
            shared_file.mime_type = getattr(uploaded, 'content_type', '') or ''
            shared_file.save()
            messages.success(request, f'"{shared_file.title}" uploaded successfully.')
            return redirect('file_list', repo_pk=repo_pk)
    else:
        form = SharedFileUploadForm()
    return render(request, 'files/upload.html', {'form': form, 'repo': repo})


def file_download(request, file_pk):
    shared_file = get_object_or_404(SharedFile, pk=file_pk)
    if not shared_file.repository.is_accessible_by(request.user):
        raise Http404
    SharedFile.objects.filter(pk=file_pk).update(download_count=shared_file.download_count + 1)
    try:
        response = FileResponse(
            shared_file.file.open('rb'),
            content_type=shared_file.mime_type or 'application/octet-stream',
            as_attachment=True,
            filename=shared_file.file_name or shared_file.title,
        )
        return response
    except Exception:
        raise Http404('File not found.')


@login_required
def file_delete(request, file_pk):
    shared_file = get_object_or_404(SharedFile, pk=file_pk)
    repo = shared_file.repository
    if not repo.is_accessible_by(request.user):
        messages.error(request, 'Access denied.')
        return redirect('file_dashboard')
    if not _can(request.user, 'delete'):
        messages.error(request, "You don't have permission to delete files.")
        return redirect('file_list', repo_pk=repo.pk)
    if request.method == 'POST':
        title = shared_file.title
        try:
            shared_file.file.delete(save=False)
        except Exception:
            pass
        shared_file.delete()
        messages.success(request, f'"{title}" deleted successfully.')
        return redirect('file_list', repo_pk=repo.pk)
    return render(request, 'files/file_confirm_delete.html', {'file': shared_file, 'repo': repo})


@login_required
def repository_create(request):
    if not _can(request.user, 'manage_repo'):
        messages.error(request, "You don't have permission to create repositories.")
        return redirect('file_dashboard')
    if request.method == 'POST':
        form = FileRepositoryForm(request.POST)
        if form.is_valid():
            repo = form.save(commit=False)
            repo.created_by = request.user
            repo.save()
            messages.success(request, f'Repository "{repo.name}" created.')
            return redirect('file_list', repo_pk=repo.pk)
    else:
        form = FileRepositoryForm()
    return render(request, 'files/repository_form.html', {'form': form, 'action': 'Create'})


@login_required
def repository_edit(request, repo_pk):
    repo = get_object_or_404(FileRepository, pk=repo_pk)
    if not _can(request.user, 'manage_repo'):
        messages.error(request, "You don't have permission to edit repositories.")
        return redirect('file_dashboard')
    if request.method == 'POST':
        form = FileRepositoryForm(request.POST, instance=repo)
        if form.is_valid():
            form.save()
            messages.success(request, f'Repository "{repo.name}" updated.')
            return redirect('file_list', repo_pk=repo.pk)
    else:
        form = FileRepositoryForm(instance=repo)
    return render(request, 'files/repository_form.html', {'form': form, 'repo': repo, 'action': 'Edit'})


@login_required
def repository_delete(request, repo_pk):
    repo = get_object_or_404(FileRepository, pk=repo_pk)
    if not _can(request.user, 'manage_repo'):
        messages.error(request, "You don't have permission to delete repositories.")
        return redirect('file_dashboard')
    if request.method == 'POST':
        name = repo.name
        for f in repo.files.all():
            try:
                f.file.delete(save=False)
            except Exception:
                pass
        repo.delete()
        messages.success(request, f'Repository "{name}" deleted.')
        return redirect('repository_list')
    return render(request, 'files/repository_confirm_delete.html', {'repo': repo})
