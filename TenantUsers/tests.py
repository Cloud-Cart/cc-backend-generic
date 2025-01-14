from rest_framework import status

from CloudCart.tests import TenantAPITestCase
from TenantUsers.choices import TenantUserRoles, InvitationStatus
from TenantUsers.models import TenantUser, TenantUserInvitation
from Users.models import User


class TestGetTenantUser(TenantAPITestCase):
    tenant_type = 'stores'

    def setUp(self):
        super().setUp()
        self.url = '/v1/store-users/self/'
        self.user = User.objects.create_user(
            first_name='John',
            last_name='Doe',
            email='john-doe@example.com'
        )
        self.client.force_authenticate(user=self.user)

    def test_success(self):
        self.tenant_user = TenantUser.objects.create(
            user=self.user,
            role=TenantUserRoles.TenantAdmin
        )
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['first_name'], 'John')
        self.assertEqual(response.data['last_name'], 'Doe')
        self.assertEqual(response.data['email'], 'john-doe@example.com')
        self.assertEqual(response.data['role'], TenantUserRoles.TenantAdmin)


class TestInviteUser(TenantAPITestCase):
    tenant_type = 'stores'

    def setUp(self):
        super().setUp()
        self.url = '/v1/store-users/invite/'
        self.user = User.objects.create_user(
            first_name='John',
            last_name='Doe',
            email='john-doe@example.com'
        )
        self.client.force_authenticate(user=self.user)

    def test_success(self):
        self.tenant_user = TenantUser.objects.create(
            user=self.user,
            role=TenantUserRoles.TenantAdmin
        )
        data = {
            'first_name': 'Jane',
            'last_name': 'Smith',
            'email': 'janesmith@example.com',
            'role': TenantUserRoles.OrderProcessor
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(email='janesmith@example.com').exists())
        new_user = User.objects.get(email='janesmith@example.com')
        self.assertTrue(TenantUser.objects.filter(user=new_user).exists())
        new_tenant_user = new_user.tenant_user
        self.assertTrue(TenantUserInvitation.objects.filter(
            invited_by=self.tenant_user,
            user=new_tenant_user,
            invitation_status=InvitationStatus.PENDING
        ))


    def test_duplicate_email(self):
        self.tenant_user = TenantUser.objects.create(
            user=self.user,
            role=TenantUserRoles.TenantAdmin
        )
        duplicate_user = User.objects.create(
            first_name='Richard',
            last_name='Roe',
            email='richardroe@example.com'
        )
        TenantUser.objects.create(
            user=duplicate_user,
            role=TenantUserRoles.OrderProcessor
        )
        data = {
            'first_name': 'Richard',
            'last_name': 'Roe',
            'email': 'richardroe@example.com',
            'role': TenantUserRoles.OrderProcessor
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)

    def test_no_permission(self):
        self.tenant_user = TenantUser.objects.create(
            user=self.user,
            role=TenantUserRoles.OrderProcessor
        )
        data = {
            'first_name': 'Richard',
            'last_name': 'Roe',
            'email': 'richardoe@example.com',
            'role': TenantUserRoles.OrderProcessor
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
