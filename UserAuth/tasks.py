from uuid import UUID

from django.conf import settings
from django.core.mail import send_mail

from CloudCart.celery import app
from UserAuth.models import OTPAuthentication
from Users.models import User


@app.task
def generate_and_send_otp(user_id: UUID):
    user = User.objects.get(pk=user_id)
    otp = OTPAuthentication.generate_otp(user)
    send_mail(
        f"Your OTP is {otp}",
        "Your OTP is {}".format(otp),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )
