"""Template context processors — make controller status available everywhere."""
from .models import ControllerStatus


def controller_status(request):
    try:
        status = ControllerStatus.current()
        return {
            "controller_online": status.is_online,
            "controller_version": status.version or "Ryu 4.34",
        }
    except Exception:
        return {"controller_online": False, "controller_version": "Ryu 4.34"}
