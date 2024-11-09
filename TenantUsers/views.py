from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from TenantUsers.models import TenantUser
from TenantUsers.permissions import CanInviteUser
from TenantUsers.serializers import TenantUserSerializer


class TenantUsersViewSet(GenericViewSet):
    queryset = TenantUser.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = TenantUserSerializer

    @action(detail=False, methods=['GET'], url_path='', url_name='get-self')
    def get_self(self, request, *args, **kwargs):
        tenant_user = request.user.tenant_user
        ser = TenantUserSerializer(tenant_user)
        return Response(ser.data)

    @action(
        url_path='invite',
        detail=False,
        methods=('POST',),
        url_name='invite-user',
        permission_classes=(CanInviteUser,),
    )
    def invite(self, request, *args, **kwargs):
        ser = TenantUserSerializer(data=request.data, context={'user': request.user})
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(ser.data, status=status.HTTP_201_CREATED)

    @action(
        url_path='accept-invite',
        detail=False,
        methods=('POST',),
        url_name='accept-invite',
        permission_classes=(AllowAny,),
    )
    def accept_invite(self, request, *args, **kwargs):
        pass
