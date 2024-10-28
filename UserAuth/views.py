from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from UserAuth.models import OTPAuthentication, HOTPAuthentication
from UserAuth.permissions import IsOwnAuthenticator
from UserAuth.serializers import RegisterSerializer, VerifyOTPSerializer, AuthenticatorAppSerializer
from UserAuth.tasks import generate_and_send_otp, send_new_authentication_app_created_email
from Users.models import User


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

    @action(
        url_path='create-hotp-authentication',
        methods=['POST'],
        serializer_class=AuthenticatorAppSerializer,
        permission_classes=[IsAuthenticated],
        detail=False
    )
    def create_hotp_authentication(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={'creating': True})
        serializer.is_valid(raise_exception=True)
        user: User = request.user
        authenticator_app: HOTPAuthentication = serializer.save(authentication=user.authentication)
        send_new_authentication_app_created_email.delay(str(user.id), str(authenticator_app.id))
        return Response(data=serializer.data, status=status.HTTP_201_CREATED)

    @action(
        url_path='activate-hotp-authentication',
        methods=['POST'],
        serializer_class=VerifyOTPSerializer,
        permission_classes=[IsOwnAuthenticator],
        detail=True,
        queryset=HOTPAuthentication.objects.all()
    )
    def activate_hotp_authentication(self, request, *args, **kwargs):
        authenticator: HOTPAuthentication = self.get_object()
        if authenticator.is_active:
            return Response(
                {
                    'error': 'Authenticator is already active',
                },
                status=status.HTTP_409_CONFLICT
            )
        ser = self.get_serializer(instance=authenticator, data=request.data)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(data=ser.data, status=status.HTTP_200_OK)
