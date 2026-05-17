from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from . import views

router = DefaultRouter()
router.register("events", views.EventViewSet)
router.register("switches", views.SwitchViewSet)
router.register("hosts", views.HostViewSet)
router.register("threats", views.ThreatViewSet)

urlpatterns = [
    path("auth/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("controller/status/", views.ControllerStatusView.as_view()),
    path("snapshot/", views.LiveSnapshotView.as_view()),
    path("", include(router.urls)),
]
