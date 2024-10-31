from django.urls import include, re_path

urlpatterns = [
    re_path(
        r'^(?P<version>(v1))/auth/',
        include('UserAuth.urls'),
    ),
    re_path(
        r'^(?P<version>(v1))/users',
        include('Users.urls'),
    ),
]
