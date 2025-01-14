from rest_framework.routers import DefaultRouter

from TenantUsers.views import TenantUsersViewSet

router = DefaultRouter()
router.register(r'', TenantUsersViewSet, basename='tenant-user')
urlpatterns = router.urls
