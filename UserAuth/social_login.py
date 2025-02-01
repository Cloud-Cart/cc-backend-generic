import jwt
import requests

from UserAuth.models import SocialAuthentications
from Users.models import User


class SocialAuthHandler:
    def __init__(self, provider, token_url, user_info_url, token_payload):
        self.provider = provider
        self.token_url = token_url
        self.user_info_url = user_info_url
        self.token_payload = token_payload
        self.user = None

    def exchange_code(self, code, redirect_uri):
        self.token_payload["code"] = code
        self.token_payload["redirect_uri"] = redirect_uri
        response = requests.post(self.token_url, data=self.token_payload)
        return response.json() if response.status_code == 200 else None

    def get_user_info(self, access_token):
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(self.user_info_url, headers=headers)
        return response.json() if response.status_code == 200 else None

    def extract_user_info(self, access_token: str, id_token: str) -> (str, str):
        if self.provider == "google" and id_token:
            payload = jwt.decode(id_token, options={"verify_signature": False})
            email = payload.get("email")
            name = payload.get("name")
            if not payload.get("email_verified"):
                raise ValueError('Email not verified')
        else:
            user_info = self.get_user_info(access_token)
            if not user_info:
                raise ValueError('User not found')
            email = user_info.get("email") or user_info.get("mail")
            name = user_info.get("displayName") or user_info.get("name")
        return email, name

    def get_or_create_user(self, email: str, name: str) -> User:
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                "username": name,
                "first_name": name.split()[0],
                "last_name": " ".join(name.split()[1:]),
            },
        )
        if created:
            user.set_unusable_password()
            user.save()
        self.user = user
        return user

    def create_auth(self):
        social_auth, created = SocialAuthentications.objects.get_or_create(
            authentication_id=self.user.authentication.id,
            account=self.provider
        )
        if not created:
            social_auth.sign_count += 1
            social_auth.save()
        return social_auth
