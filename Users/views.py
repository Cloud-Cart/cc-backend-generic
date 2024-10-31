from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from Users.serializers import UserSerializer


class UsersViewSet(GenericViewSet):
    @action(
        methods=["GET"],
        detail=False,
        permission_classes=[IsAuthenticated],
        url_path='me',
        serializer_class=UserSerializer,
        url_name='get-me'
    )
    def get_self(self, request, *args, **kwargs):
        user = request.user
        ser = self.get_serializer(user)
        return Response(ser.data)

    @action(
        methods=["PATCH"],
        detail=False,
        permission_classes=[IsAuthenticated],
        url_path='update-self',
        serializer_class=UserSerializer,
        url_name='update'
    )
    def update_self(self, request, *args, **kwargs):
        user = request.user
        ser: UserSerializer = self.get_serializer(user, data=request.data)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(ser.data, status=status.HTTP_200_OK)
