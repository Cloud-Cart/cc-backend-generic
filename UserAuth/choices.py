from django.db.models import IntegerChoices
from django.db.models.enums import TextChoices
from django.utils.translation import gettext_lazy as _


class OTPPurpose(IntegerChoices):
    VERIFY_EMAIL = (1, _('Verify Email'))
    SECOND_STEP_VERIFICATION = (2, _('Second Step Verification'))


class DefaultAuthenticationMethod(TextChoices):
    PASSWORD_SIGNIN = ('password', _('Password'))
    PASSKEY_SIGNIN = ('passkey', _('Pass Key'))
    GOOGLE_SOCIAL_SIGNIN = ('google', _('Google Social Sign in'))
    FACEBOOK_SIGNIN = ('facebook', _('Facebook Sign in'))
    APPLE_SIGNIN = ('apple', _('Apple Sign in'))

    __empty__ = _('No Default')

class SocialAuthenticationMethod(TextChoices):
    GOOGLE = ('google', _('Google Social Sign in'))
    FACEBOOK = ('facebook', _('Facebook Sign in'))
    MICROSOFT = ('microsoft', _('Microsoft Sign in'))
