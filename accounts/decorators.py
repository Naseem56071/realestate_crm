from functools import wraps
from django.contrib import messages
from django.shortcuts import redirect
from django.http import HttpResponseForbidden


def role_required(allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):

            # Not logged in
            if not request.user.is_authenticated:
                return redirect("login")

            # Logged in but wrong role
            if request.user.role not in allowed_roles:
                messages.error(
                    request, "You do not have permission to access this page."
                )
                return HttpResponseForbidden("403 Forbidden")

            return view_func(request, *args, **kwargs)

        return wrapper
    return decorator
