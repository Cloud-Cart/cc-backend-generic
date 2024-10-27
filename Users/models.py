import uuid

from django.contrib.auth.models import AbstractUser
from django.db.models import EmailField, UUIDField, BooleanField
from django.utils.translation import gettext_lazy as _

from Users.managers import UserManager


class User(AbstractUser):
    id = UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = None
    email = EmailField(_("Email Address"), unique=True)
    is_email_verified = BooleanField(default=False, verbose_name=_("Is Email Verified"))
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = [
        "first_name",
        "last_name",
    ]
    objects = UserManager()

    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'

