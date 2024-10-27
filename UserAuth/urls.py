from django.urls import path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView

from UserAuth.views import AuthenticationViewSet

router = DefaultRouter()
router.register('', AuthenticationViewSet, basename='auth')

urlpatterns = [
    path('login/', TokenObtainPairView.as_view(), name='login'),
]
urlpatterns += router.urls

app_name = 'UserAuth'
