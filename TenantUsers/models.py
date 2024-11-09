from uuid import uuid4

from django.db.models import Model, OneToOneField, CASCADE, UUIDField, CharField, ForeignKey
from django.utils.translation import gettext_lazy as _

from TenantUsers.choices import TenantUserRoles, InvitationStatus
from Users.models import User


class TenantUser(Model):
    id = UUIDField(primary_key=True, default=uuid4, editable=False)
    user = OneToOneField(User, verbose_name=_('User'), on_delete=CASCADE, related_name='tenant_user')
    role = CharField(_('Role'), choices=TenantUserRoles.choices, max_length=100)

    class Meta:
        verbose_name = _('Tenant User')
        verbose_name_plural = _('Tenant Users')
        db_table = 'tenant_user'

    def __str__(self):
        return str(self.user)


class TenantUserInvitation(Model):
    invited_by = ForeignKey(
        TenantUser,
        verbose_name=_('Invited by'),
        on_delete=CASCADE,
        related_name='invited_users',
    )
    invitation_status = CharField(
        _('Invitation status'),
        choices=InvitationStatus.choices,
        max_length=100,
    )
    user = OneToOneField(
        TenantUser,
        verbose_name=_('User'),
        on_delete=CASCADE,
        related_name='invitation',
    )

    class Meta:
        verbose_name = _('Tenant User invitation')
        verbose_name_plural = _('Tenant User invitations')
        db_table = 'tenant_user_invitation'
