import random
from datetime import timedelta
from uuid import uuid4

from django.contrib.auth.hashers import make_password, check_password
from django.db.models import Model, CASCADE, OneToOneField, UUIDField, Index, CharField, DateTimeField
from django.utils import timezone

from Users.models import User


class OTPAuthentication(Model):
    id = UUIDField(primary_key=True, default=uuid4, editable=False)
    user = OneToOneField(User, on_delete=CASCADE, related_name='otp')
    otp_hash = CharField(max_length=128, null=True)
    expires_at = DateTimeField(null=True)

    class Meta:
        db_table = 'otp_authentication'
        verbose_name = 'OTP Authentication'
        verbose_name_plural = 'OTP Authentication'
        indexes = [
            Index(fields=['user']),
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
    def generate_otp(cls, user: User) -> int:
        otp = random.randint(100000, 999999)
        obj = cls.objects.create(user=user)
        obj.set_otp(otp)
        obj.save()
        return otp
