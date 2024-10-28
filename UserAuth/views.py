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

    @action(
        detail=True,
        methods=["POST"],
        serializer_class=VerifyOTPSerializer,
        url_path='verify-otp',
        lookup_field='authentication__user_id',
        lookup_url_kwarg='pk',
        queryset=OTPAuthentication
    )
    def verify_otp(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance=instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            'success': True,
        })


