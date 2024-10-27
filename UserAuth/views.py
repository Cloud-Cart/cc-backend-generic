from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from UserAuth.serializers import RegisterSerializer


class AuthenticationViewSet(GenericViewSet):
    @action(
        detail=False,
        methods=["POST"],
        serializer_class=RegisterSerializer
    )
    def register(self, request, *args, **kwargs):
        ser = self.get_serializer(data=request.data)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(data=ser.data, status=status.HTTP_201_CREATED)
