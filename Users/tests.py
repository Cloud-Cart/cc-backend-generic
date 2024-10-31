from django_tenants.test.cases import TenantTestCase
from rest_framework import status
from rest_framework.reverse import reverse
from rest_framework.test import APITestCase

from CloudCart.tests import TenantAPIClient
from Users.models import User


class TestGetSelf(APITestCase, TenantTestCase):
    def setUp(self):
        self.client = TenantAPIClient(self.tenant)
        self.url = reverse('users-get-me', ('v1',))

    def test_success(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='password'
        )
        self.client.force_authenticate(user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK, "Status Code should be 200")
        response_data = response.json()
        self.assertEqual(response_data['id'], str(user.id), "Should return same user")


class TestUpdateSelf(APITestCase, TenantTestCase):
    def setUp(self):
        self.client = TenantAPIClient(self.tenant)
        self.url = reverse('users-update', ('v1',))

    def test_success(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='password',
            first_name='test',
            last_name='1',
        )
        self.client.force_authenticate(user)
        first_name = 'first name'
        last_name = 'last name'
        data = {
            'first_name': first_name,
            'last_name': last_name,
        }
        response = self.client.patch(
            path=self.url,
            data=data,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, "Status Code should be 200")
        response_data = response.json()
        self.assertEqual(response_data['id'], str(user.id), "Should return same user")
        user.refresh_from_db()
        self.assertEqual(str(user.id), response_data['id'], 'Should return same user')
        self.assertEqual(first_name, user.first_name, "Should update first name")
        self.assertEqual(last_name, user.last_name, "Should update last name")

    def test_email_update(self):
        email = 'test@test.com'
        user = User.objects.create_user(
            email=email,
            password='password',
        )
        self.client.force_authenticate(user)
        new_email = 'test1@test.com'
        data = {
            'email': new_email,
        }
        response = self.client.patch(
            path=self.url,
            data=data,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, "Status Code should be 200")
        response_data = response.json()
        self.assertEqual(response_data['id'], str(user.id), "Should return same user")
        user.refresh_from_db()
        self.assertEqual(email, user.email, 'Should not update email')
