from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import ValidationError
from rest_framework.fields import CharField, EmailField, ChoiceField, UUIDField
from rest_framework.serializers import Serializer

from CloudCart.celery import app
from TenantUsers.choices import TenantUserRoles
from TenantUsers.models import TenantUser
from Users.models import User


class InviteUserSerializer(Serializer):
    id = UUIDField(read_only=True)
    first_name = CharField(source='user.first_name')
    last_name = CharField(source='user.last_name')
    email = EmailField(source='user.email')
    role = ChoiceField(choices=TenantUserRoles.choices)

    @staticmethod
    def validate_email(value: str):
        if User.objects.filter(email__iexact=value).exists():
            raise ValidationError(_('Email already registered.'))
        return value

    def create(self, validated_data):
        user_data = validated_data.pop('user')
        role = validated_data.pop('role')
        user = User.objects.create(
            **user_data,
            is_active=False
        )
        inviting_user = self.context.get('user')
        tenant_user = TenantUser.objects.create(
            user=user,
            role=role,
            invited_by=inviting_user,
        )
        app.send_task('invite_tenant_user', args=[str(tenant_user.id)])
        return tenant_user
