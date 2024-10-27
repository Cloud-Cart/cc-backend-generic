from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from UserAuth.models import OTPAuthentication
from UserAuth.serializers import RegisterSerializer, VerifyOTPSerializer
from UserAuth.tasks import generate_and_send_otp


class AuthenticationViewSet(GenericViewSet):
    @action(
        detail=False,
        methods=["POST"],
        serializer_class=RegisterSerializer
    )
    def register(self, request, *args, **kwargs):
        ser = self.get_serializer(data=request.data)
        ser.is_valid(raise_exception=True)
        user = ser.save()
        generate_and_send_otp.delay(str(user.id))
        return Response(data=ser.data, status=status.HTTP_201_CREATED)
