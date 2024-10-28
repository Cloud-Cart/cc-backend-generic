from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from UserAuth.models import OTPAuthentication, HOTPAuthentication, Authentication
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
        serializer.save(authentication=user.authentication)
        return Response(data=serializer.data, status=status.HTTP_201_CREATED)

    @action(
        url_path='activate-hotp-authentication',
        methods=['PATCH'],
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
        send_new_authentication_app_created_email.delay(str(request.user.id), str(authenticator.id))
        return Response(data=ser.data, status=status.HTTP_200_OK)

    @action(
        detail=False,
        methods=["PATCH"],
        url_path='enable-otp-authentication',
        permission_classes=[IsAuthenticated],
    )
    def enable_otp_authentication(self, request, *args, **kwargs):
        auth: Authentication = request.user.authentication
        if auth.otp_2fa_enabled:
            return Response(
                {
                    'error': 'OTP Verification is already enabled',
                },
                status=status.HTTP_409_CONFLICT
            )

        if not auth.email_verified:
            return Response(
                {
                    'error': 'Email not verified to enable OTP authentication',
                },
                status=status.HTTP_409_CONFLICT
            )

        auth.otp_2fa_enabled = True
        auth.save()
        return Response(data={}, status=status.HTTP_200_OK)

    @action(
        detail=False,
        methods=["PATCH"],
        url_path='disable-otp-authentication',
        permission_classes=[IsAuthenticated],
    )
    def disable_otp_authentication(self, request, *args, **kwargs):
        auth: Authentication = request.user.authentication
        if not auth.otp_2fa_enabled:
            return Response(
                {
                    'error': 'OTP Verification is already disabled',
                },
                status=status.HTTP_409_CONFLICT
            )
        auth.otp_2fa_enabled = False
        auth.save()
        return Response(data={}, status=status.HTTP_200_OK)

    @action(
        detail=False,
        methods=["PATCH"],
        url_path='enable-2fa-authentication',
        permission_classes=[IsAuthenticated],
    )
    def enable_2fa_authentication(self, request, *args, **kwargs):
        auth: Authentication = request.user.authentication
        if auth.otp_2fa_enabled:
            return Response(
                {
                    'error': '2FA already enabled',
                },
                status=status.HTTP_409_CONFLICT
            )
        is_authenticator_apps = auth.hotp_authentications.filter(is_active=True).exists()
        if not (is_authenticator_apps or auth.otp_2fa_enabled):
            return Response(
                {
                    'error': 'Setup OTP Verification or Authenticator before enabling 2FA authentication',
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        auth.is_2fa_enabled = True
        auth.save()
        return Response(data={}, status=status.HTTP_200_OK)

    @action(
        detail=False,
        methods=["PATCH"],
        url_path='disable-2fa-authentication',
        permission_classes=[IsAuthenticated],
    )
    def disable_2fa_authentication(self, request, *args, **kwargs):
        auth: Authentication = request.user.authentication
        if not auth.otp_2fa_enabled:
            return Response(
                {
                    'error': '2FA already disabled',
                },
                status=status.HTTP_409_CONFLICT
            )
        auth.is_2fa_enabled = False
        auth.save()
        return Response(data={}, status=status.HTTP_200_OK)
