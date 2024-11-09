from django_tenants.test.cases import TenantTestCase
from django_tenants.test.client import TenantClient
from rest_framework.test import APIClient, APITestCase

from Tenants.models import Tenant


class TenantAPITestCase(APITestCase, TenantTestCase):
    tenant_type = ''

    @classmethod
    def setup_tenant(cls, tenant: Tenant):
        tenant.type = cls.tenant_type
        return tenant

    def setUp(self):
        super().setUp()
        self.client = TenantAPIClient(self.tenant, self.domain)


class TenantAPIClient(TenantClient, APIClient):
    domain = None

    def __init__(self, tenant, domain, *args, **kwargs):
        self.domain = domain
        super().__init__(tenant=tenant, *args, **kwargs)

    def generic(self, *args, **kwargs):
        if "HTTP_HOST" not in kwargs:
            kwargs["HTTP_HOST"] = self.domain.domain
        request = super().generic(*args, **kwargs)
        # Assign the tenant to the request object
        request.tenant = self.tenant
        return request
