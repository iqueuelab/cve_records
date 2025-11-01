from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import CVEHistoryViewSet, CVEDashboardView, CVELineChartView

router = DefaultRouter()
router.register(r'cve-history', CVEHistoryViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('dashboard/', CVEDashboardView.as_view(), name='cve_dashboard'),
    path('chart/line/', CVELineChartView.as_view(), name='line_chart'),
]