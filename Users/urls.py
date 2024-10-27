from rest_framework.routers import DefaultRouter

from Users.views import UsersViewSet

router = DefaultRouter()
router.register(r'', UsersViewSet, basename='users')

urlpatterns = router.urls
