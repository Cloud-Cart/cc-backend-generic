from rest_framework.decorators import action
from rest_framework.viewsets import GenericViewSet


class UsersViewSet(GenericViewSet):
    @action(
        methods=["POST"],
        detail=False,
    )
    def invite_user(self, request, *args, **kwargs):
        pass
