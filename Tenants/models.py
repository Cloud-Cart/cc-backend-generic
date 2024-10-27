import uuid

from django.db.models import UUIDField, CharField, ForeignKey, CASCADE
from django.utils.translation import gettext_lazy as _
from django_tenants.models import TenantMixin, DomainMixin


class Tenant(TenantMixin):
    id = UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant_name = CharField(max_length=255)
    owner = ForeignKey('Users.User', on_delete=CASCADE)
    auto_create_schema = True

    class Meta:
        verbose_name = _('Tenant')
        verbose_name_plural = _('Tenants')
        db_table = 'tenants'


class Domain(DomainMixin):
    class Meta:
        db_table = 'domains'
        verbose_name = _('Domain')
        verbose_name_plural = _('Domains')
