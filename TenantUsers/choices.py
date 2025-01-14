from django.db.models import TextChoices
from django.utils.translation import gettext_lazy as _


class TenantUserRoles(TextChoices):
    TenantAdmin = 'tenant_admin', _('Tenant Admin')
    InventoryManager = 'inventory_manager', _('Inventory Manager')
    OrderProcessor = 'order_processor', _('Order Processor')
    CustomerService = 'customer_service', _('Customer Service')
    MarketingSpecialist = 'marketing_specialist', _('Marketing Specialist')
    Customer = 'customer', _('Customer')


class InvitationStatus(TextChoices):
    PENDING = 'pending', _('Pending')
    SEND = 'send', _('Send')
    ACCEPTED = 'accepted', _('Accepted')
    REJECTED = 'rejected', _('Rejected')
    RESEND = 'resend', _('Resend')

    __empty__ = _('Not yet')
