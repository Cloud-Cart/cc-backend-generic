from django.db.models import IntegerChoices
from django.utils.translation import gettext_lazy as _


class OTPPurpose(IntegerChoices):
    VERIFY_EMAIL = (1, _('Verify Email'))
    SECOND_STEP_VERIFICATION = (2, _('Second Step Verification'))


class DefaultAuthenticationMethod(IntegerChoices):
    PASSWORD_SIGNIN = (1, _('Password'))
    PASSKEY_SIGNIN = (2, _('Pass Key'))
    GOOGLE_SOCIAL_SIGNIN = (3, _('Google Social Sign in'))
    FACEBOOK_SIGNIN = (4, _('Facebook Sign in'))
    APPLE_SIGNIN = (5, _('Apple Sign in'))

    __empty__ = _('No Default')

