from django_tenants.test.client import TenantClient
from rest_framework.test import APIClient


class TenantAPIClient(TenantClient, APIClient):
    def __init__(self, tenant, *args, **kwargs):
        super().__init__(tenant=tenant, *args, **kwargs)