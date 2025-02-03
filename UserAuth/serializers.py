import os
import re

from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import ValidationError
from rest_framework.fields import CharField, SerializerMethodField, EmailField
from rest_framework.serializers import ModelSerializer, Serializer

from UserAuth.models import Authentication, HOTPAuthentication, OTPAuthentication, IncompleteLoginSessions, \
    RecoveryCode, SecondStepVerificationConfig
from Users.models import User


class AuthenticationMethodsSerializer(ModelSerializer):
    is_password_available = SerializerMethodField(read_only=True)
    is_passkey_available = SerializerMethodField(read_only=True)
    social_accounts = SerializerMethodField(read_only=True)
    email = EmailField()

    class Meta:
        model = Authentication
        fields = [
            'email',
            'is_password_available',
            'is_passkey_available',
            'social_accounts',
            'default_method'
        ]
        extra_kwargs = {
            'default_method': {
                'read_only': True,
            },
        }

    def validate_email(self, value: str) -> str:
        try:
            self.instance = Authentication.objects.get(email=value)
        except Authentication.DoesNotExist:
            raise ValidationError(_('Email does not exist'))
        if not self.instance.user.is_active:
            raise ValidationError(_('Account is inactive'))
        return value

    @staticmethod
    def get_is_password_available(obj: Authentication):
        return bool(obj.password)

    @staticmethod
    def get_is_passkey_available(obj: Authentication):
        return obj.webauthn_credentials.all().exists()

    @staticmethod
    def get_social_accounts(obj: Authentication):
        return list(obj.social_authentications.all().values_list('account', flat=True))


class RegisterSerializer(ModelSerializer):
    confirm_password = CharField(write_only=True)
    password = CharField(write_only=True, )

    class Meta:
        model = User
        fields = [
            'id',
            'email',
            'password',
            'confirm_password',
        ]
        extra_kwargs = {
            'password': {
                'write_only': True,
                'min_length': 8,
            }
        }

    def validate(self, attrs):
        confirm_password = attrs.pop('confirm_password')
        password = attrs.get('password')
        if password != confirm_password:
            raise ValidationError(_('Passwords not match.'))
        return attrs

    def save(self):
        password = self.validated_data.pop('password')
        email = self.validated_data.get('email')
        self.instance = User.objects.create_user(email=email, password=password, is_active=False)
        return self.instance


class VerifyEmailOTPSerializer(Serializer):
    otp = CharField(write_only=True)

    class Meta:
        model = OTPAuthentication

    def validate_otp(self, value):
        if not self.instance:
            raise AssertionError('Pass instance to validate VerifyOTPSerializer.')
        if not self.instance.verify_otp(value):
            raise ValidationError(_('Invalid OTP.'))
        return value

    def save(self):
        auth: Authentication = self.instance.authentication
        auth.email_verified = True
        auth.save()
        user = auth.user
        user.is_active = True
        user.save()
        self.instance.delete()
        return user

    def to_representation(self, instance):
        return AuthenticatorAppSerializer(instance).data


class AuthenticatorAppSerializer(ModelSerializer):
    class Meta:
        model = HOTPAuthentication
        fields = [
            'id',
            'name',
            'is_active',
            'created_at',
            'second_step_config_id'
        ]
        extra_kwargs = {
            'is_active': {'read_only': True},
            'created_at': {'read_only': True},
            'second_step_config_id': {'read_only': True},
        }

    def validate_name(self, value):
        auth_id = self.context.get('auth_id', None)
        if auth_id is not None:
            if self.Meta.model.objects.filter(authentication_id=auth_id, name=value).exists():
                raise ValidationError(_('You already used this name.'))
        return value

    def to_representation(self, instance: HOTPAuthentication):
        data = super().to_representation(instance)
        if self.context.get('creating'):
            data['secret'] = instance.secret
        return data


class LoginSerializer(Serializer):
    incomplete_session = None
    tokens = None
    email = EmailField(
        write_only=True,
        required=True,
    )
    password = CharField(
        write_only=True,
        required=True,
    )

    class Meta:
        model = Authentication
        fields = [
            'email',
            'password'
        ]

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        try:
            auth = Authentication.objects.get(email=email)
        except Authentication.DoesNotExist:
            raise ValidationError({
                'email': _('User does not exist.')
            })
        if not (auth.email_verified and auth.user.is_active):
            raise ValidationError({
                'email': _('User is inactive.')
            })
        if not auth.check_password(password):
            raise ValidationError({
                'password': _('Password is incorrect.')
            })
        self.instance = auth
        return attrs

    def save(self):
        if self.instance.is_2fa_enabled:
            IncompleteLoginSessions.objects.filter(auth=self.instance).delete()
            self.incomplete_session = IncompleteLoginSessions.objects.create(auth=self.instance)
        else:
            self.tokens = self.instance.auth_tokens
            self.instance.user.last_login = timezone.now()
            self.instance.user.save()
        return self.instance

    def to_representation(self, instance):
        if instance.is_2fa_enabled:
            return {
                'session_id': self.incomplete_session.id
            }
        return self.tokens


class TwoFactorSettingsSerializer(ModelSerializer):
    apps = AuthenticatorAppSerializer(many=True, read_only=True, source='hotp_authentications')
    email = SerializerMethodField()

    class Meta:
        model = SecondStepVerificationConfig
        fields = [
            'is_2fa_enabled',
            'otp_2fa_enabled',
            'apps',
            'email',
            'hotp_verfication_enabled'
        ]
        extra_kwargs = {
            'is_2fa_enabled': {
                'read_only': True,
            },
            'otp_2fa_enabled': {
                'read_only': True,
            }
        }

    @staticmethod
    def get_email(instance: SecondStepVerificationConfig):
        if not (instance.otp_2fa_enabled and instance.email_verified):
            return None
        match = re.match(r"([^@]+)@(.+)", instance.email)
        if not match:
            return None
        return f"{match.group(1)[:3]}****@{match.group(2)}"


class VerifyHOTPAppSerializer(Serializer):
    otp = CharField(write_only=True)

    def validate(self, attrs):
        otp: str = attrs.get('otp')
        config: SecondStepVerificationConfig = self.instance

        if not config.is_2fa_enabled:
            raise ValidationError(_('2 Step Verification not enabled.'))

        if not config.hotp_authentications.filter(is_active=True).exists():
            raise ValidationError(_('OTP verification failed. Use any of the available method.'))
        if not self.verify_authenticator_app(otp):
            raise ValidationError(_('OTP verification failed. Invalid OTP'))
        return attrs

    def verify_authenticator_app(self, otp):
        auth: Authentication = self.instance
        for app in auth.hotp_authentications.filter(is_active=True):
            if app.verify_otp(otp, window=1):
                app.last_used = timezone.now()
                app.save()
                return True
        return False

    def save(self, **kwargs):
        IncompleteLoginSessions.objects.filter(auth_id=self.instance.authentication_id).delete()

    def to_representation(self, instance: Authentication):
        return instance.auth_tokens


class RecoverAccountSerializer(Serializer):
    email = CharField(write_only=True, required=True)
    recovery_code = CharField(write_only=True, required=True)
    password = CharField(write_only=True, required=True)
    confirm_password = CharField(write_only=True, required=True)
    recovery_obj = None

    def validate(self, attrs):
        email = attrs.get('email')
        recovery_code = attrs.get('recovery_code')
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')
        errors = {}
        if password != confirm_password:
            errors['confirm_password'] = _('Passwords do not match.')

        try:
            self.instance = Authentication.objects.get(email=email)
        except Authentication.DoesNotExist:
            errors['email'] = _('User does not exist.')
            raise ValidationError(errors)
        try:
            self.recovery_obj = RecoveryCode.objects.get(
                authentication=self.instance,
                code=recovery_code,
                is_used=False,
            )
        except RecoveryCode.DoesNotExist:
            errors['recovery_code'] = _('Recovery code does not exist.')
            raise ValidationError(errors)
        if len(errors.keys()) > 0:
            raise ValidationError(errors)
        return attrs

    def save(self, **kwargs):
        password = self.validated_data.get('password')
        self.instance.set_password(password)
        self.instance.save()
        self.recovery_obj.is_used = True
        self.recovery_obj.save()
        self.instance.is_2fa_enabled = False
        self.instance.save()
        return self.instance

    def to_representation(self, instance):
        return instance.auth_tokens


class RecoveryCodeSerializer(ModelSerializer):
    class Meta:
        model = RecoveryCode
        fields = (
            'code',
            'is_used',
        )
        kwargs = {
            'code': {
                'read_only': True,
            },
            'is_used': {
                'read_only': True,
            }
        }


class UpdatePasswordSerializer(Serializer):
    password = CharField(required=True, write_only=True)
    new_password = CharField(required=True, write_only=True)
    confirm_password = CharField(required=True, write_only=True)

    def validate(self, attrs):
        password = attrs.get('password')
        new_password = attrs.get('new_password')
        confirm_password = attrs.get('confirm_password')

        errors = {}
        if self.instance is None:
            raise AssertionError('Can\'t update password without instance.')
        if not self.instance.check_password(password):
            errors['password'] = _('Password does not valid.')
        if new_password != confirm_password:
            errors['confirm_password'] = _('Passwords do not match.')

        if errors:
            raise ValidationError(errors)
        return attrs

    def save(self, **kwargs):
        self.instance.set_password(self.validated_data.get('new_password'))
        self.instance.save()
        return self.instance


class BeginRegisterPasskeySerializer(Serializer):
    challenge = SerializerMethodField()
    user_id = CharField(read_only=True)
    username = CharField(read_only=True, source='user.email')
    display_name = CharField(read_only=True, source='user.full_name')
    exclude_credentials = SerializerMethodField()

    @staticmethod
    def get_challenge(instance: Authentication):
        return os.urandom(32)

    @staticmethod
    def get_exclude_credentials(instance: Authentication):
        return []
