from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import ValidationError
from rest_framework.fields import CharField, EmailField, ChoiceField, UUIDField
from rest_framework.relations import PrimaryKeyRelatedField
from rest_framework.serializers import Serializer

from CloudCart.celery import app
from TenantUsers.choices import TenantUserRoles, InvitationStatus
from TenantUsers.models import TenantUser, TenantUserInvitation
from Users.models import User


class TenantUserSerializer(Serializer):
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
        inviting_user: User = self.context.get('user')
        tenant_user = TenantUser.objects.create(
            user=user,
            role=role,
        )
        invitation = TenantUserInvitation.objects.create(
            invited_by=inviting_user.tenant_user,
            invitation_status=InvitationStatus.PENDING,
            user=tenant_user,
        )
        app.send_task('invite_tenant_user', args=[str(invitation.id)])
        return tenant_user


class TenantUserInviteAcceptSerializer(Serializer):
    tenant_user = PrimaryKeyRelatedField(queryset=TenantUser.objects.filter(
        invitation__invitation_status__in=[InvitationStatus.SEND, InvitationStatus.RESEND]
    ))
    secret = CharField(write_only=True)
    password = CharField(write_only=True)
    confirm_password = CharField(write_only=True)

    def validate(self, attrs):
        errors = {}
        tenant_user = attrs.pop('tenant_user')
        secret = attrs.pop('secret')
        password = attrs.pop('password')
        confirm_password = attrs.pop('confirm_password')
        invitation = None
        try:
            invitation = TenantUserInvitation.objects.get(user=tenant_user)
            if not invitation.verify_secret(secret):
                errors['secret'] = _('Incorrect secret.')
        except TenantUserInvitation.DoesNotExist:
            errors['tenant_user'] = _('Invitation can\'t be found.')
        if password != confirm_password:
            errors['confirm_password'] = _('Passwords do not match.')
        if errors:
            raise ValidationError(errors)
        self.instance = invitation
        return attrs

    def save(self):
        password = self.validated_data.pop('password')

        invitation = self.instance
        invitation.secret_hash = None
        invitation.invitation_status = InvitationStatus.ACCEPTED
        invitation.save()
        user = invitation.user.user
        user.is_active = True
        user.save()
        auth = user.authentication
        auth.set_password(password)
        auth.save()
        return invitation
