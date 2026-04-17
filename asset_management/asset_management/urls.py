from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from assets import error_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),
    path('', include('assets.urls')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Custom error handlers
handler400 = error_views.error_400
handler403 = error_views.error_403
handler404 = error_views.error_404
handler500 = error_views.error_500

admin.site.site_header = 'Asset Management System'
admin.site.site_title = 'AMS Admin'
admin.site.index_title = 'Asset Management Administration'
