from django.urls import path
from . import views

urlpatterns = [
    path("gnn/infer/", views.GnnInferView.as_view(), name="gnn_infer"),
    path("gnn/status/", views.GnnStatusView.as_view(), name="gnn_status"),
]
