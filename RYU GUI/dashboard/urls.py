from django.urls import path
from django.contrib.auth.decorators import login_required
from . import views

app_name = "dashboard"

urlpatterns = [
    path("", login_required(views.DashboardView.as_view()), name="index"),
    path("switches/", login_required(views.SwitchesView.as_view()), name="switches"),
    path("hosts/", login_required(views.HostsView.as_view()), name="hosts"),
    path("links/", login_required(views.LinksView.as_view()), name="links"),
    path("flows/", login_required(views.FlowsView.as_view()), name="flows"),
    path("groups/", login_required(views.GroupsView.as_view()), name="groups"),
    path("meters/", login_required(views.MetersView.as_view()), name="meters"),
    path("topology/", login_required(views.TopologyView.as_view()), name="topology"),
    path("threats/", login_required(views.ThreatsView.as_view()), name="threats"),
    path("config/", login_required(views.ConfigView.as_view()), name="config"),
    path("logs/", login_required(views.LogsView.as_view()), name="logs"),
    path("settings/", login_required(views.SettingsView.as_view()), name="settings"),
]
