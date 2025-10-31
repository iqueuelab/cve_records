from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import CVEHistoryViewSet

router = DefaultRouter()
router.register(r'cve-history', CVEHistoryViewSet)

urlpatterns = [
    path('', include(router.urls)),
]