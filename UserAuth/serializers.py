from django.contrib.auth.hashers import make_password
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import ValidationError
from rest_framework.fields import CharField
from rest_framework.serializers import ModelSerializer, Serializer, IntegerField

from UserAuth.models import Authentication
from Users.models import User


class RegisterSerializer(ModelSerializer):
    confirm_password = CharField(write_only=True)
    password = CharField(write_only=True,)

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


class VerifyOTPSerializer(Serializer):
    otp = IntegerField(write_only=True)

    def validate_otp(self, value):
        if not self.instance:
            raise AssertionError('Pass instance to validate VerifyOTPSerializer.')
        if not self.instance.verify_otp(value):
            raise ValidationError(_('OTP verification failed.'))
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

    class Meta:
        fields = [
            'otp'
        ]
