from django.urls import path
from .views import health_check, analyze_alert, analyze_file

urlpatterns = [
    path("health/", health_check),
    path("analyze/manual/", analyze_alert),
    path("analyze/file/", analyze_file),
]