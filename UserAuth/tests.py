from django_tenants.test.cases import TenantTestCase
from rest_framework import status
from rest_framework.reverse import reverse
from rest_framework.test import APITestCase

from CloudCart.tests import TenantAPIClient
from UserAuth.choices import OTPPurpose
from UserAuth.models import OTPAuthentication, HOTPAuthentication, IncompleteLoginSessions
from UserAuth.utils import generate_recovery_codes
from Users.models import User


class TestRegistration(APITestCase, TenantTestCase):
    def setUp(self):
        super().setUp()
        self.url = reverse('auth-register', ('v1',))
        self.client = TenantAPIClient(self.tenant)

    def test_success(self):
        data = {
            'email': 'test@test.com',
            'password': '<PASSWORD>',
            'confirm_password': '<PASSWORD>',
        }
        response = self.client.post(
            self.url,
            data=data,
        )
        response_data = response.json()
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, 'Response code should be 201')
        self.assertEqual(User.objects.count(), 1, 'User should be created')
        self.assertIn('id', response_data, 'ID should be returned in response')
        self.assertEqual(response_data['id'], str(User.objects.first().id), 'ID should be the id of created user')
        self.assertIn('email', response_data, 'Email should be returned in response')
        self.assertEqual(response_data['email'], data['email'], 'Email should be changed')

    def test_not_equal_password(self):
        data = {
            'email': 'test@test.com',
            'password': '<PASSWORD>',
            'confirm_password': '<PASSWORD1>',
        }
        response = self.client.post(
            self.url,
            data=data,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(User.objects.count(), 0)

    def test_duplicate_email(self):
        User.objects.create_user(email='test@test.com', password='<PASSWORD>', first_name='first_user', )
        data = {
            'email': 'test@test.com',
            'password': '<PASSWORD>',
            'confirm_password': '<PASSWORD>',
        }
        response = self.client.post(
            self.url,
            data=data,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(User.objects.count(), 1)


class TestOTPVerification(APITestCase, TenantTestCase):
    def setUp(self):
        super().setUp()
        self.client = TenantAPIClient(self.tenant)

    def test_success(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
            first_name='user',
        )
        auth = user.authentication
        otp = OTPAuthentication.generate_otp(auth, OTPPurpose.VERIFY_EMAIL)
        data = {
            'otp': otp
        }
        url = reverse('auth-verify-otp', ('v1', str(user.id)))
        response = self.client.post(
            url,
            data=data,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, 'Response code should be 200')
        auth.refresh_from_db()
        user.refresh_from_db()
        self.assertTrue(auth.email_verified, 'Email should be verified')
        self.assertTrue(user.is_active, 'User should be active')
        self.assertIsNone(OTPAuthentication.objects.filter(authentication=auth).first(), "OTP should be deleted")

    def test_invalid_otp(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
            first_name='owner',
        )
        auth = user.authentication
        OTPAuthentication.generate_otp(auth, OTPPurpose.VERIFY_EMAIL)
        data = {
            'otp': '000000'
        }
        url = reverse('auth-verify-otp', ('v1', str(user.id)))
        response = self.client.post(
            url,
            data=data,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, 'Response code should be 400')

    def test_no_otp(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
            first_name='owner',
        )
        data = {
            'otp': '000000'
        }
        url = reverse('auth-verify-otp', ('v1', str(user.id)))
        response = self.client.post(
            url,
            data=data,
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND, "Response should be 404")


class TestLogin(APITestCase, TenantTestCase):
    def setUp(self):
        super().setUp()
        self.url = reverse('auth-login', ('v1',))
        self.client = TenantAPIClient(self.tenant)

    def test_success(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
            first_name='user',
        )
        user.is_active = True
        user.save()
        auth = user.authentication
        auth.email_verified = True
        auth.save()
        data = {
            'email': 'test@test.com',
            'password': '<PASSWORD>',
        }
        response = self.client.post(
            self.url,
            data=data,
        )
        response_data = response.json()
        self.assertEqual(response.status_code, status.HTTP_200_OK, 'Response code should be 200')
        self.assertIn('access', response_data, "Response should contain access token")
        self.assertIn('refresh', response_data, "Response should contain refresh token")

    def test_invalid_password(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
            first_name='user',
        )
        user.is_active = True
        user.save()
        auth = user.authentication
        auth.email_verified = True
        auth.save()
        data = {
            'email': 'test@test.com',
            'password': '<PASSWORD1>',
        }
        response = self.client.post(
            self.url,
            data=data,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, 'Response code should be 400')

    def test_no_user(self):
        data = {
            'email': 'test@test.com',
            'password': '<PASSWORD>',
        }
        response = self.client.post(
            self.url,
            data=data,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, "Response should be 400")

    def test_inactive_user(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
            first_name='user',
        )
        user.is_active = False
        user.save()
        auth = user.authentication
        auth.email_verified = True
        auth.save()
        data = {
            'email': 'test@test.com',
            'password': '<PASSWORD>',
        }
        response = self.client.post(
            self.url,
            data=data,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, "Response should be 400")

    def test_unverified_user(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        user.is_active = True
        user.save()
        auth = user.authentication
        auth.email_verified = False
        auth.save()
        data = {
            'email': 'test@test.com',
            'password': '<PASSWORD>',
        }
        response = self.client.post(
            self.url,
            data=data,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, "Response should be 400")


class TestCreateHotp(APITestCase, TenantTestCase):
    def setUp(self):
        self.url = reverse('auth-create-hotp-authentication', ('v1',))
        self.client = TenantAPIClient(self.tenant)

    def test_success(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        self.client.force_authenticate(user)
        data = {
            'name': "Test HOTP"
        }
        response = self.client.post(
            self.url,
            data=data,
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, 'Response code should be 200')
        response_data = response.json()
        self.assertIn('name', response_data, "Response should contain name")
        self.assertIn('secret', response_data, "Response should contain secret")
        self.assertEqual(user.authentication.hotp_authentications.count(), 1, 'One HOTP should be created')
        authenticator: HOTPAuthentication = user.authentication.hotp_authentications.first()
        self.assertFalse(authenticator.is_active, 'Authenticator should be active')

    def test_duplicate_name(self):
        duplicate_name = 'authenticator'
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        HOTPAuthentication.objects.create(
            authentication_id=user.authentication.id,
            name=duplicate_name,
            is_active=True,
        )
        self.client.force_authenticate(user)
        data = {
            'name': duplicate_name
        }
        response = self.client.post(
            self.url,
            data=data,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, "Response should be 400")
        response_data = response.json()
        self.assertIn('name', response_data, "Response should error for \'name\'")

    def test_required_parameters(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        self.client.force_authenticate(user)
        data = {
        }
        response = self.client.post(
            self.url,
            data=data,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, "Response should be 400")
        response_data = response.json()
        self.assertIn('name', response_data, "Response should error for \'name\'")


class TestActivateHotp(APITestCase, TenantTestCase):
    def setUp(self):
        self.client = TenantAPIClient(self.tenant)

    def test_success(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        self.client.force_authenticate(user)
        auth_app = HOTPAuthentication.objects.create(
            authentication_id=user.authentication.id,
            name='Test HOTP',
            is_active=False,
        )
        url = reverse('auth-activate-hotp-authentication', ('v1', str(auth_app.id)))
        data = {
            'otp': auth_app.now()
        }
        response = self.client.patch(
            path=url,
            data=data,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, 'Response should be 200')
        response_data = response.json()
        self.assertIn('name', response_data, "Response should error for \'name\'")
        auth_app.refresh_from_db()
        self.assertTrue(auth_app.is_active, 'Authenticator should be active')

    def test_invalid_otp(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        self.client.force_authenticate(user)
        auth_app = HOTPAuthentication.objects.create(
            authentication_id=user.authentication.id,
            name='Test HOTP',
        )
        data = {
            'otp': '<PASSWORD>'
        }
        url = reverse('auth-activate-hotp-authentication', ('v1', str(auth_app.id)))
        response = self.client.patch(
            path=url,
            data=data,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, "Response should be 400")
        response_data = response.json()
        self.assertIn('otp', response_data, "Response should error for \'otp\'")
        auth_app.refresh_from_db()
        self.assertFalse(auth_app.is_active, 'Authenticator should not be active')

    def test_invalid_app(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        self.client.force_authenticate(user)
        data = {
            'otp': '<PASSWORD>'
        }
        url = reverse('auth-activate-hotp-authentication', ('v1', str(user.id)))
        response = self.client.patch(
            path=url,
            data=data,
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND, "Response should be 404")

    def test_app_already_active(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        self.client.force_authenticate(user)
        auth_app = HOTPAuthentication.objects.create(
            authentication_id=user.authentication.id,
            name='Test HOTP',
            is_active=True,
        )
        data = {
            'otp': auth_app.now()
        }
        url = reverse('auth-activate-hotp-authentication', ('v1', str(auth_app.id)))
        response = self.client.patch(
            path=url,
            data=data
        )
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT, "Response should be 409")


class TestEnableOTPAuthentication(APITestCase, TenantTestCase):
    def setUp(self):
        self.client = TenantAPIClient(self.tenant)
        self.url = reverse('auth-enable-otp-authentication', ('v1',))

    def test_success(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        auth = user.authentication
        auth.email_verified = True
        auth.save()
        self.client.force_authenticate(user)
        response = self.client.patch(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK, 'Response should be 200')
        auth.refresh_from_db()
        self.assertTrue(auth.otp_2fa_enabled, 'OTP verification should be enabled')

    def test_email_not_verified(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        auth = user.authentication
        auth.email_verified = False
        auth.save()
        self.client.force_authenticate(user)
        response = self.client.patch(self.url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN, "Response should be 400")
        auth.refresh_from_db()
        self.assertFalse(auth.otp_2fa_enabled, 'OTP verification should be disabled')

    def test_otp_already_enabled(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        auth = user.authentication
        auth.email_verified = True
        auth.otp_2fa_enabled = True
        auth.save()
        self.client.force_authenticate(user)
        response = self.client.patch(self.url)
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT, "Response should be 409")
        auth.refresh_from_db()
        self.assertTrue(auth.otp_2fa_enabled, 'OTP verification should be enabled')


class TestDisableOTPAuthentication(APITestCase, TenantTestCase):
    def setUp(self):
        self.client = TenantAPIClient(self.tenant)
        self.url = reverse('auth-disable-otp-authentication', ('v1',))

    def test_success(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        auth = user.authentication
        auth.email_verified = True
        auth.otp_2fa_enabled = True
        self.client.force_authenticate(user)
        response = self.client.patch(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK, 'Response should be 200')
        auth.refresh_from_db()
        self.assertFalse(auth.otp_2fa_enabled, 'OTP verification should be enabled')

    def test_otp_verification_already_disabled(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        auth = user.authentication
        auth.otp_2fa_enabled = False
        self.client.force_authenticate(user)
        response = self.client.patch(self.url)
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT, "Response should be 409")
        auth.refresh_from_db()
        self.assertFalse(auth.otp_2fa_enabled, 'OTP verification should be disabled')


class TestEnable2FAAuthentication(APITestCase, TenantTestCase):
    def setUp(self):
        self.client = TenantAPIClient(self.tenant)
        self.url = reverse('auth-enable-2fa-authentication', ('v1',))

    def test_success_with_otp(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        auth = user.authentication
        auth.email_verified = True
        auth.otp_2fa_enabled = True
        auth.save()
        self.client.force_authenticate(user)
        response = self.client.patch(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK, 'Response should be 200')
        auth.refresh_from_db()
        self.assertTrue(auth.is_2fa_enabled, '2fa verification should be enabled')

    def test_success_with_hotp(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        auth = user.authentication
        auth.email_verified = True
        auth.otp_2fa_enabled = False
        auth.save()
        HOTPAuthentication.objects.create(
            authentication_id=user.authentication.id,
            name='Test HOTP',
            is_active=True,
        )
        self.client.force_authenticate(user)
        response = self.client.patch(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK, 'Response should be 200')
        auth.refresh_from_db()
        self.assertTrue(auth.is_2fa_enabled, '2fa verification should be enabled')

    def test_success_without_method(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        auth = user.authentication
        auth.email_verified = True
        auth.otp_2fa_enabled = False
        auth.save()
        self.client.force_authenticate(user)
        response = self.client.patch(self.url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, 'Response should be 400')
        auth.refresh_from_db()
        self.assertFalse(auth.is_2fa_enabled, '2fa verification should be enabled')


class TestDisable2FAAuthentication(APITestCase, TenantTestCase):
    def setUp(self):
        self.client = TenantAPIClient(self.tenant)
        self.url = reverse('auth-disable-2fa-authentication', ('v1',))

    def test_success(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        auth = user.authentication
        auth.email_verified = True
        auth.is_2fa_enabled = True
        auth.otp_2fa_enabled = True
        auth.save()

        self.client.force_authenticate(user)
        response = self.client.patch(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK, 'Response should be 200')
        auth.refresh_from_db()
        self.assertFalse(auth.is_2fa_enabled, '2fa verification should be disabled')

    def test_2fa_verification_already_disabled(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        auth = user.authentication
        auth.email_verified = True
        auth.is_2fa_enabled = False
        auth.otp_2fa_enabled = True
        auth.save()
        self.client.force_authenticate(user)
        response = self.client.patch(self.url)
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT, "Response should be 409")
        auth.refresh_from_db()
        self.assertFalse(auth.is_2fa_enabled, '2fa verification should be disabled')


class TestGet2FAAuthentication(APITestCase, TenantTestCase):
    def setUp(self):
        self.client = TenantAPIClient(self.tenant)
        self.url = reverse('auth-get-2fa-settings', ('v1',))

    def test_success(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        self.client.force_authenticate(user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK, 'Response should be 200')


class TestRequest2FAAuthentication(APITestCase, TenantTestCase):
    def setUp(self):
        self.client = TenantAPIClient(self.tenant)
        self.url = reverse('auth-request-2fa-otp', ('v1',))

    def test_success(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        auth = user.authentication
        self.client.force_authenticate(user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK, 'Response should be 200')
        otp: OTPAuthentication = OTPAuthentication.objects.filter(authentication=auth).first()
        self.assertIsNotNone(otp, 'otp should be created')
        self.assertEqual(otp.otp_purpose, OTPPurpose.SECOND_STEP_VERIFICATION)


class TestTwoSetupLoginProcess(APITestCase, TenantTestCase):
    def setUp(self):
        self.client = TenantAPIClient(self.tenant)
        self.login_url = reverse('auth-login', ('v1',))
        self.request_otp_url = reverse('auth-request-2fa-otp', ('v1',))
        self.complete_login_url = reverse('auth-complete-login', ('v1',))
        self.email = 'test@test.com'
        self.password = '<PASSWORD>'
        self.user = User.objects.create_user(
            email=self.email,
            password=self.password,
        )
        self.auth = self.user.authentication
        self.auth.email_verified = True
        self.auth.is_2fa_enabled = True
        self.auth.save()

    def test_login_with_2step_enabled_account(self):
        data = {
            'email': self.email,
            'password': self.password,
        }
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, status.HTTP_206_PARTIAL_CONTENT, 'Response should be 206')
        response_data = response.json()
        self.assertIn('session_id', response_data, 'Response should contain session id')
        session_id = response_data['session_id']
        login_session = IncompleteLoginSessions.objects.filter(auth_id=self.auth.id).first()
        self.assertIsNotNone(login_session, 'login session should be created')
        self.assertEqual(str(session_id), str(login_session.id), 'Created and returned session id should be same')

    def test_complete_login_with_authenticator(self):
        hotp = HOTPAuthentication.objects.create(
            authentication_id=self.auth.id,
            name='Test HOTP',
            is_active=True,
        )
        session = IncompleteLoginSessions.objects.create(
            auth_id=self.auth.id,
        )
        data = {
            'authenticator_otp': hotp.now()
        }
        headers = {
            'Incomplete-Session': str(session.id)
        }
        response = self.client.post(
            path=self.complete_login_url,
            data=data,
            headers=headers,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, 'Response should be 200')
        response_data = response.json()
        self.assertIn('access', response_data, 'Response should contain access')
        self.assertIn('refresh', response_data, 'Response should contain refresh')

    def test_login_with_otp(self):
        session = IncompleteLoginSessions.objects.create(
            auth_id=self.auth.id,
        )
        self.auth.otp_2fa_enabled = True
        self.auth.save()
        otp = OTPAuthentication.generate_otp(
            self.auth,
            OTPPurpose.SECOND_STEP_VERIFICATION
        )
        data = {
            'email_otp': otp
        }
        headers = {
            'Incomplete-Session': str(session.id)
        }
        response = self.client.post(
            path=self.complete_login_url,
            data=data,
            headers=headers,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, 'Response should be 200')
        response_data = response.json()
        self.assertIn('access', response_data, 'Response should contain access')
        self.assertIn('refresh', response_data, 'Response should contain refresh')

    def test_fail_email_otp(self):
        session = IncompleteLoginSessions.objects.create(
            auth_id=self.auth.id,
        )
        self.auth.otp_2fa_enabled = True
        self.auth.save()
        OTPAuthentication.generate_otp(
            auth=self.auth,
            purpose=OTPPurpose.SECOND_STEP_VERIFICATION,
        )
        data = {
            'email_otp': '000000'
        }
        headers = {
            'Incomplete-Session': str(session.id)
        }
        response = self.client.post(
            path=self.complete_login_url,
            data=data,
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, 'Response should be 400')

    def test_fail_authenticator_otp(self):
        session = IncompleteLoginSessions.objects.create(
            auth_id=self.auth.id,
        )
        HOTPAuthentication.objects.create(
            authentication_id=self.auth.id,
            is_active=True,
            name='Test HOTP',
        )
        data = {
            'authenticator_otp': '000000'
        }
        headers = {
            'Incomplete-Session': str(session.id)
        }
        response = self.client.post(
            path=self.complete_login_url,
            data=data,
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, 'Response should be 400')


class TestRecoveryAccount(APITestCase, TenantTestCase):
    def setUp(self):
        self.client = TenantAPIClient(self.tenant)
        self.url = reverse('auth-recover-account', ('v1',))

    def test_recover_account_success(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        new_password = 'new-password'
        auth = user.authentication
        recovery_obj = auth.recovery_codes.all().first()
        data = {
            'email': user.email,
            'password': new_password,
            'confirm_password': new_password,
            'recovery_code': recovery_obj.code,
        }
        response = self.client.post(
            path=self.url,
            data=data,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, 'Response should be 200')
        response_data = response.json()
        self.assertIn('access', response_data, 'Response should contain access')
        self.assertIn('refresh', response_data, 'Response should contain refresh')
        recovery_obj.refresh_from_db()
        self.assertTrue(recovery_obj.is_used, 'Recovery code should be marked as used')
        auth.refresh_from_db()
        self.assertTrue(auth.check_password(new_password), 'Password should match')

    def test_recover_account_password_not_match(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        new_password = 'password1'
        confirm_password = 'password2'
        auth = user.authentication
        recovery_obj = auth.recovery_codes.all().first()
        data = {
            'email': user.email,
            'password': new_password,
            'confirm_password': confirm_password,
            'recovery_code': recovery_obj.code,
        }
        response = self.client.post(
            path=self.url,
            data=data,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, 'Response should be 400')

    def test_recovery_code_not_match(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        password = 'password'
        auth = user.authentication
        data = {
            'email': user.email,
            'password': password,
            'confirm_password': password,
            'recovery_code': generate_recovery_codes(),
        }
        response = self.client.post(
            path=self.url,
            data=data,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, 'Response should be 400')

    def test_recovery_code_already_used(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        auth = user.authentication
        recovery_obj = auth.recovery_codes.all().first()
        recovery_obj.is_used = True
        recovery_obj.save()
        new_password = 'password'
        data = {
            'email': user.email,
            'password': new_password,
            'confirm_password': new_password,
            'recovery_code': recovery_obj.code,
        }
        response = self.client.post(
            path=self.url,
            data=data
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, 'Response should be 400')

    def test_no_user_found(self):
        password = 'password'
        data = {
            'email': 'test@test.com',
            'password': password,
            'confirm_password': password,
            'recovery_code': generate_recovery_codes(),
        }
        response = self.client.post(
            path=self.url,
            data=data
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, 'Response should be 400')


class TestGetRecoveryCodes(APITestCase, TenantTestCase):
    def setUp(self):
        self.client = TenantAPIClient(self.tenant)
        self.url = reverse('auth-get-recovery-codes', ('v1',))

    def test_get_recovery_codes_success(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        self.client.force_authenticate(user)
        auth = user.authentication
        recovery_codes = auth.recovery_codes.all()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK, 'Response should be 200')
        response_data = response.json()
        self.assertEqual(len(response_data), 10, 'Response should contain 10 items')
        self.assertEqual(
            set(code.code for code in recovery_codes),
            set(code['code'] for code in response_data),
            "All recovery code should be present in response"
        )


class TestResetRecoveryCodes(APITestCase, TenantTestCase):
    def setUp(self):
        self.client = TenantAPIClient(self.tenant)
        self.url = reverse('auth-reset-recovery-codes', ('v1',))

    def test_reset_recovery_codes_success(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        self.client.force_authenticate(user)
        auth = user.authentication
        recovery_codes = set(code.code for code in auth.recovery_codes.all())
        response = self.client.put(
            path=self.url,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, 'Response should be 200')
        response_data = response.json()
        new_recovery_codes = auth.recovery_codes.all()
        self.assertEqual(len(response_data), len(new_recovery_codes), 'Response should contain 10 items')
        self.assertNotEqual(
            recovery_codes,
            set(
                code.code
                for code in new_recovery_codes
            ),
            'All codes should be reset'
        )


class TestPasswordUpdate(APITestCase, TenantTestCase):
    def setUp(self):
        self.client = TenantAPIClient(self.tenant)
        self.url = reverse('auth-update-password', ('v1',))

    def test_success(self):
        password = 'password'
        user = User.objects.create_user(
            email='test@test.com',
            password=password,
        )
        self.client.force_authenticate(user)
        auth = user.authentication
        new_password = 'password1'
        data = {
            'password': password,
            'new_password': new_password,
            'confirm_password': new_password
        }
        response = self.client.put(
            path=self.url,
            data=data
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, 'Response should be 200')
        auth.refresh_from_db()
        self.assertTrue(auth.check_password(new_password), 'Password should update successfully')

    def test_current_password_not_match(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        self.client.force_authenticate(user)
        auth = user.authentication
        data = {
            'password': 'wrong_password',
            'new_password': 'password1',
            'confirm_password': 'password1'
        }
        response = self.client.put(
            path=self.url,
            data=data
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, 'Response should be 400')
        auth.refresh_from_db()
        self.assertFalse(auth.check_password(data['new_password']), 'Password should not update')

    def test_new_password_not_match(self):
        user = User.objects.create_user(
            email='test@test.com',
            password='<PASSWORD>',
        )
        self.client.force_authenticate(user)
        data = {
            'password': '<PASSWORD>',
            'new_password': 'password1',
            'confirm_password': 'password2'
        }
        response = self.client.put(
            path=self.url,
            data=data
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, 'Response should be 400')
