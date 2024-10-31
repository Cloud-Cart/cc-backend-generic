from rest_framework.routers import DefaultRouter

from UserAuth.views import AuthenticationViewSet

router = DefaultRouter()
router.register('', AuthenticationViewSet, basename='auth')
urlpatterns = router.urls
