from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from TenantUsers.models import TenantUser
from TenantUsers.permissions import CanInviteUser
from TenantUsers.serializers import InviteUserSerializer


class TenantUsersViewSet(GenericViewSet):
    queryset = TenantUser.objects.all()

    @action(
        url_path='invite',
        detail=False,
        methods=('POST',),
        url_name='invite-user',
        serializer_class=InviteUserSerializer,
        permission_classes=(CanInviteUser,),
    )
    def invite(self, request):
        ser = InviteUserSerializer(data=request.data, context={'user': request.user})
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(ser.data, status=status.HTTP_201_CREATED)
