from rest_framework import permissions

class IsAdminUser(permissions.BasePermission):
    """
    Custom permission to only allow admin users.
    """

    def has_permission(self, request, view):
        # Check if the user is authenticated and if they are an admin
        return bool(request.user and request.user.is_authenticated and request.user.is_admin)