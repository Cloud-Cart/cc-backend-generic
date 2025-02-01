from rest_framework import exceptions
from rest_framework.response import Response
from rest_framework.views import exception_handler


class APIException(exceptions.APIException):
    status_code = 400
    default_code = 'error'
    default_detail = 'A server error occurred.'

    def __init__(self, detail=None, code=None):
        if detail is None:
            detail = self.default_detail
        if code is None:
            code = self.default_code

        if isinstance(detail, tuple):
            detail = list(detail)

        self.code = code
        self.detail = detail

        super().__init__(detail=detail, code=code)


def custom_exception_handler(exc, context):
    if isinstance(exc, APIException):
        response_data = {
            'code': exc.code,
            'detail': exc.detail,
        }
        return Response(response_data, status=exc.status_code)
    return exception_handler(exc, context)
