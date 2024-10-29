from django.db.models import IntegerChoices
from django.utils.translation import gettext_lazy as _


class OTPPurpose(IntegerChoices):
    VERIFY_EMAIL = (1, _('Verify Email'))
    SECOND_STEP_VERIFICATION = (2, _('Second Step Verification'))
