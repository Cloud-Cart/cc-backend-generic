import random
from datetime import timedelta
from uuid import uuid4

from django.contrib.auth.hashers import make_password, check_password, acheck_password, is_password_usable
from django.db.models import Model, CASCADE, OneToOneField, UUIDField, Index, CharField, DateTimeField, EmailField, \
    BooleanField, ForeignKey
from django.utils import timezone

from UserAuth.utils import generate_recovery_codes
from Users.models import User


class OTPAuthentication(Model):
    id = UUIDField(primary_key=True, default=uuid4, editable=False)
    authentication = OneToOneField('Authentication', on_delete=CASCADE, related_name='otp')
    otp_hash = CharField(max_length=128, null=True)
    expires_at = DateTimeField(null=True)

    class Meta:
        db_table = 'otp_authentication'
        verbose_name = 'OTP Authentication'
        verbose_name_plural = 'OTP Authentication'
        indexes = [
            Index(fields=['authentication']),
        ]

    def set_otp(self, otp, validity_minutes=5):
        """Hash the OTP using Django's password hashing framework."""
        self.otp_hash = make_password(str(otp))
        self.expires_at = timezone.now() + timedelta(minutes=validity_minutes)

    def verify_otp(self, otp):
        """Verify if the provided OTP matches the stored hash and is not expired."""
        if timezone.now() > self.expires_at:
            return False
        return check_password(str(otp), self.otp_hash)

    @classmethod
    def generate_otp(cls, auth: 'Authentication') -> int:
        otp = random.randint(100000, 999999)
        obj = cls.objects.create(authentication=auth)
        obj.set_otp(otp)
        obj.save()
        return otp

    def __str__(self):
        return f"OTP of {self.authentication}"


class Authentication(Model):
    id = UUIDField(primary_key=True, default=uuid4, editable=False)
    user = OneToOneField(User, on_delete=CASCADE, related_name='authentication')
    password = CharField(max_length=128, null=True)
    email = EmailField(max_length=128)
    email_verified = BooleanField(default=False)

    is_2fa_enabled = BooleanField(default=False)
    otp_2fa_enabled = BooleanField(default=False)

    is_recovery_generated = BooleanField(default=False)
    recovery_email = EmailField(max_length=128, null=True)

    _password = None

    class Meta:
        db_table = 'authentication'
        verbose_name = 'Authentication'
        verbose_name_plural = 'Authentication'
        indexes = [
            Index(fields=['user']),
        ]

    def __str__(self):
        return f"Authentication of {self.user}"

    def save(
            self,
            *args,
            **kwargs
    ):
        generate_codes = False
        if not self.is_recovery_generated:
            self.is_recovery_generated = True
            generate_codes = True
        result = super().save(*args, **kwargs)
        if generate_codes:
            for _ in range(10):
                RecoveryCode.objects.create(authentication=self)
        return result

    def set_password(self, raw_password):
        self.password = make_password(raw_password)
        self._password = raw_password

    def check_password(self, raw_password):
        """
        Return a boolean of whether the raw_password was correct. Handles
        hashing formats behind the scenes.
        """

        def setter(raw_password):
            self.set_password(raw_password)
            # Password hash upgrades shouldn't be considered password changes.
            self._password = None
            self.save(update_fields=["password"])

        return check_password(raw_password, self.password, setter)

    async def acheck_password(self, raw_password):
        """See check_password()."""

        async def setter(raw_password):
            self.set_password(raw_password)
            # Password hash upgrades shouldn't be considered password changes.
            self._password = None
            await self.asave(update_fields=["password"])

        return await acheck_password(raw_password, self.password, setter)

    def set_unusable_password(self):
        # Set a value that will never be a valid hash
        self.password = make_password(None)

    def has_usable_password(self):
        """
        Return False if set_unusable_password() has been called for this user.
        """
        return is_password_usable(self.password)


class HOTPAuthentication(Model):
    id = UUIDField(primary_key=True, default=uuid4, editable=False)
    authentication = ForeignKey(Authentication, on_delete=CASCADE, related_name='hotp_authentications')
    secret = CharField(max_length=128, null=True)
    name = CharField(max_length=128, null=True)

    class Meta:
        db_table = 'hotp_authentication'
        verbose_name = 'HOTP Authentication'
        verbose_name_plural = 'HOTP Authentication'
        indexes = [
            Index(fields=['authentication']),
        ]

    def __str__(self):
        return f"{self.name} of {self.authentication}"


class RecoveryCode(Model):
    id = UUIDField(primary_key=True, default=uuid4, editable=False)
    code = CharField(max_length=128, default=generate_recovery_codes)
    is_used = BooleanField(default=False)
    authentication = ForeignKey(Authentication, on_delete=CASCADE, related_name='recovery_codes')

    class Meta:
        db_table = 'recovery_codes'
        verbose_name = 'Recovery Code'
        verbose_name_plural = 'Recovery Codes'

    def __str__(self):
        return f"{self.authentication}"
