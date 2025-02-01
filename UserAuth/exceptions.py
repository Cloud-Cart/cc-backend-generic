from rest_framework import status

from CloudCart.error_codes import ErrorCodes
from CloudCart.exceptions import APIException


class UserNotFoundException(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    default_code = ErrorCodes.email_not_found


class UserLoginDeniedException(APIException):
    default_code = ErrorCodes.login_denied
    status_code = status.HTTP_403_FORBIDDEN