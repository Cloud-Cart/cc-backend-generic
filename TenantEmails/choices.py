from django.db.models import TextChoices
from django.utils.translation import gettext_lazy as _


class EmailTypeChoice(TextChoices):
    INVITE_EMAIL = 'invite_email', _('Invite Email')
