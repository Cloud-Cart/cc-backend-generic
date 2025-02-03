from rest_framework.routers import DefaultRouter


from UserAuth.views import AuthenticationViewSet, SocialLoginViewSet, LoginViewSet

router = DefaultRouter()
router.register('', AuthenticationViewSet, basename='auth')
router.register('social-login', SocialLoginViewSet, basename='social-login')
router.register('login', LoginViewSet, basename='login')
urlpatterns = router.urls
