from django.http import JsonResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response

from .ai_agent import analyze_log_with_ai
from .parsers import prepare_log_for_ai


def health_check(request):
    return JsonResponse({
        "status": "ok",
        "service": "soc-agent-api"
    })


@api_view(["POST"])
def analyze_alert(request):
    alert_text = request.data.get("alert", "")

    if not alert_text.strip():
        return Response(
            {"error": "Alert text is empty"},
            status=400
        )

    try:
        parsed = prepare_log_for_ai(alert_text)

        analysis = analyze_log_with_ai(
            log_text=parsed["content"],
            source=f"manual:{parsed['log_type']}",
            log_type=parsed["log_type"],
            risk_score=parsed.get("risk_score", 0),
            parser_indicators=parsed.get("indicators", []),
        )

        analysis["parser"] = {
            "log_type": parsed["log_type"],
            "total_lines": parsed["total_lines"],
            "selected_lines": parsed["selected_lines"],
        }

        return Response(analysis)

    except Exception as error:
        return Response(
            {
                "error": "AI analysis failed",
                "details": str(error),
            },
            status=500
        )


@api_view(["POST"])
def analyze_file(request):
    uploaded_file = request.FILES.get("file")

    if uploaded_file is None:
        return Response(
            {"error": "No file uploaded"},
            status=400
        )

    try:
        file_content = uploaded_file.read().decode("utf-8", errors="ignore")

        if not file_content.strip():
            return Response(
                {"error": "Uploaded file is empty"},
                status=400
            )

        parsed = prepare_log_for_ai(file_content)

        analysis = analyze_log_with_ai(
            log_text=parsed["content"],
            source=f"{uploaded_file.name}:{parsed['log_type']}",
            log_type=parsed["log_type"],
            risk_score=parsed.get("risk_score", 0),
            parser_indicators=parsed.get("indicators", []),
        )

        analysis["filename"] = uploaded_file.name
        analysis["parser"] = {
            "log_type": parsed["log_type"],
            "total_lines": parsed["total_lines"],
            "selected_lines": parsed["selected_lines"],
            "risk_score": parsed.get("risk_score", 0),
            "indicators": parsed.get("indicators", []),
        }

        return Response(analysis)

    except Exception as error:
        return Response(
            {
                "error": "File analysis failed",
                "details": str(error),
            },
            status=500
        )