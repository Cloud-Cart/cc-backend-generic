from uuid import UUID

from django.conf import settings

from CloudCart.celery import app
from UserAuth.models import OTPAuthentication, HOTPAuthentication
from Users.models import User


@app.task
def generate_and_send_otp(user_id: UUID):
    user: User = User.objects.get(pk=user_id)
    otp = OTPAuthentication.generate_otp(user.authentication)
    user.email_user(
        subject=f"Your OTP is {otp}",
        message=f"Your OTP is {otp}",
        from_email=settings.DEFAULT_FROM_EMAIL,
    )

@app.task
def send_new_authentication_app_created_email(user_id: UUID, authenticator_id: UUID):
    user: User = User.objects.get(pk=user_id)
    authenticator: HOTPAuthentication = HOTPAuthentication.objects.get(pk=authenticator_id)
    user.email_user(
        subject="New Authentication App added to your account.",
        message=f"Your Authentication App {authenticator.name} added to your account.",
        from_email=settings.DEFAULT_FROM_EMAIL,
    )
