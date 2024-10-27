from __future__ import absolute_import, unicode_literals

import os

from tenant_schemas_celery.app import CeleryApp as TenantAwareCeleryApp

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CloudCart.settings')
app = TenantAwareCeleryApp('CloudCart')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()
