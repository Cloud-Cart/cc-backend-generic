from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import ValidationError
from rest_framework.fields import CharField
from rest_framework.serializers import ModelSerializer, Serializer, IntegerField

from Users.models import User


class RegisterSerializer(ModelSerializer):
    confirm_password = CharField(
        write_only=True,
    )

    def validate(self, attrs):
        confirm_password = attrs.pop('confirm_password')
        password = attrs.get('password')
        if password != confirm_password:
            raise ValidationError(_('Passwords not match.'))
        return attrs

    def save(self):
        password = self.validated_data.pop('password')
        instance = super().save()
        instance.set_password(password)
        instance.save()
        return instance

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
