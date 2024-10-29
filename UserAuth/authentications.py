from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from UserAuth.models import IncompleteLoginSessions


class IncompleteLoginAuthentication(BaseAuthentication):
    def authenticate(self, request):
        session_id = self.authenticate_header(request)
        if not session_id:
            return None

        try:
            session = IncompleteLoginSessions.objects.get(pk=session_id)
        except IncompleteLoginSessions.DoesNotExist:
            raise AuthenticationFailed('No Session found with this ID')

        return session.auth.user, session_id

    def authenticate_header(self, request):
        return request.headers.get('Incomplete-Session')
