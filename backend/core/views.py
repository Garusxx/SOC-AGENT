from django.http import JsonResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response

def health_check(request):
    return JsonResponse({
        "status": "ok",
        "service": "soc-agent-api"
    })


@api_view(["POST"])
def analyze_alert(request):
    alert_text = request.data.get("alert", "")

    return Response(
        {
            "severity": "High",
            "mitre": "T1059.001",
            "classification": "Suspicious PowerShell Activity",
            "recommendations": [
                "Review parent process",
                "Check user activity",
                "Investigate endpoint",
            ],
            "received_chars": len(alert_text),
        }
    )
