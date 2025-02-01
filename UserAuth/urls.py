from rest_framework.routers import DefaultRouter


from UserAuth.views import AuthenticationViewSet, SocialLoginViewSet

router = DefaultRouter()
router.register('', AuthenticationViewSet, basename='auth')
router.register('social-login', SocialLoginViewSet, basename='social-login')
urlpatterns = router.urls
