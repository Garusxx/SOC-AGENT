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


@api_view(["POST"])
def analyze_file(request):
    uploaded_file = request.FILES.get("file")

    if uploaded_file is None:
        return Response(
            {"error": "No file uploaded"},
            status=400
        )

    file_content = uploaded_file.read().decode("utf-8", errors="ignore")

    return Response(
        {
            "severity": "Medium",
            "mitre": "T1059",
            "classification": "Uploaded Log File Analysis",
            "recommendations": [
                "Review suspicious commands",
                "Check related user activity",
                "Correlate with endpoint logs",
            ],
            "filename": uploaded_file.name,
            "received_chars": len(file_content),
        }
    )