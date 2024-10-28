from uuid import UUID

from django.conf import settings

from CloudCart.celery import app
from UserAuth.models import OTPAuthentication
from Users.models import User


@app.task
def generate_and_send_otp(user_id: UUID):
    user: User = User.objects.get(pk=user_id)
    otp = OTPAuthentication.generate_otp(user.authentication)
    user.email_user(
        subject=f"Your OTP is {otp}",
        message=f"Your OTP is {otp}",
        from_email=settings.DEFAULT_FROM_EMAIL,
        fail_silently=False,
    )
