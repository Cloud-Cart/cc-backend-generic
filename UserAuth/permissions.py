from rest_framework.permissions import IsAuthenticated

from UserAuth.models import HOTPAuthentication


class IsOwnAuthenticator(IsAuthenticated):
    def has_object_permission(self, request, view, obj: HOTPAuthentication):
        return request.user.id == obj.authentication.user_id
