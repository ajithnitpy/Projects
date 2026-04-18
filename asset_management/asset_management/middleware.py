import logging
from django.shortcuts import redirect
from django.contrib import messages
from django.http import Http404
from django.core.exceptions import PermissionDenied, SuspiciousOperation

logger = logging.getLogger(__name__)


class ExceptionRedirectMiddleware:
    """Catch unhandled exceptions and redirect to home with a user-friendly message."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        # Let Django's built-in handlers deal with these — they render our
        # custom 404/403/400 templates.
        if isinstance(exception, (Http404, PermissionDenied, SuspiciousOperation)):
            return None

        # Log the real error server-side so it isn't silently swallowed.
        logger.exception(
            "Unhandled exception on %s %s: %s",
            request.method,
            request.path,
            exception,
        )

        # Redirect to home (or login if anonymous) with a friendly flash message.
        messages.error(
            request,
            "Something went wrong. Please try again or contact your administrator.",
        )
        if request.user.is_authenticated:
            return redirect('dashboard')
        return redirect('login')
