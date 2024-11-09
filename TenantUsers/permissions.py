from rest_framework.permissions import BasePermission

from TenantUsers.choices import TenantUserRoles


class CanInviteUser(BasePermission):
    def has_permission(self, request, view):
        return (
                request.user and
                request.user.is_authenticated and
                request.user.tenant_user.role == TenantUserRoles.TenantAdmin
        )
