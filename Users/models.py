import uuid

from django.contrib.auth.models import AbstractUser
from django.db.models import UUIDField, BooleanField, CharField, EmailField
from django.utils.translation import gettext_lazy as _

from Users.managers import UserManager


class User(AbstractUser):
    id = UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    first_name = CharField(_("First Name"), max_length=150, blank=True)
    last_name = CharField(_("Last Name"), max_length=150, blank=True)
    is_staff = BooleanField(
        _("Staff Status"),
        default=False,
        help_text=_("Designates whether the user can log into this admin site."),
    )
    email = EmailField(_("Email Address"), unique=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = [
        "first_name",
        "last_name",
    ]
    username = None
    password = None
    objects = UserManager()

    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def set_password(self, raw_password):
        return self.authentication.set_password(raw_password)

    def check_password(self, raw_password):
        return self.authentication.check_password(raw_password)

    async def acheck_password(self, raw_password):
        return await self.authentication.acheck_password(raw_password)

    def set_unusable_password(self):
        return self.authentication.set_unusable_password()

    def has_usable_password(self):
        return self.authentication.has_usable_password()
