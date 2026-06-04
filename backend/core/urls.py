from django.urls import path
from .views import health_check, analyze_alert

urlpatterns = [
    path("health/", health_check),
    path("analyze/manual/", analyze_alert),
]