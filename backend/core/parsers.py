SUSPICIOUS_SYSMON_KEYWORDS = [
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "rundll32",
    "regsvr32",
    "mshta",
    "certutil",
    "bitsadmin",
    "wmic",
    "psexec",
    "mimikatz",
    "lsass",
    "procdump",
    "-enc",
    "encodedcommand",
    "downloadstring",
    "invoke-webrequest",
    "invoke-expression",
    "iex",
    "http://",
    "https://",
    "temp",
    "appdata",
]


def detect_log_type(content: str) -> str:
    lower = content.lower()

    if (
        "sysmon" in lower
        or "processguid" in lower
        or "parentimage" in lower
        or "grantedaccess" in lower
        or "eventid: 1" in lower
        or "eventid: 3" in lower
        or "eventid: 10" in lower
    ):
        return "sysmon"

    if (
        "powershell" in lower
        or "-enc" in lower
        or "encodedcommand" in lower
    ):
        return "powershell"

    if (
        "eventid: 4624" in lower
        or "eventid: 4625" in lower
        or "eventid: 4672" in lower
    ):
        return "windows-security"

    return "generic"


def calculate_risk_score(content: str) -> tuple[int, list[str]]:
    lower = content.lower()

    score = 0
    indicators = []

    rules = [
        ("powershell", 15, "PowerShell"),
        ("-enc", 30, "EncodedCommand"),
        ("encodedcommand", 30, "EncodedCommand"),
        ("executionpolicy bypass", 20, "ExecutionPolicy Bypass"),
        ("invoke-webrequest", 20, "Invoke-WebRequest"),
        ("downloadstring", 20, "DownloadString"),
        ("iex", 20, "Invoke-Expression"),
        ("lsass", 50, "LSASS Access"),
        ("mimikatz", 50, "Mimikatz"),
        ("procdump", 40, "ProcDump"),
        ("certutil", 25, "CertUtil"),
        ("bitsadmin", 25, "BitsAdmin"),
        ("rundll32", 20, "RunDLL32"),
        ("regsvr32", 20, "Regsvr32"),
        ("mshta", 25, "MSHTA"),
    ]

    for keyword, points, name in rules:
        if keyword in lower:
            score += points
            indicators.append(name)

    return score, indicators


def parse_sysmon_log(content: str, max_lines: int = 200) -> dict:
    lines = content.splitlines()

    interesting_lines = []

    for line in lines:
        line_lower = line.lower()

        if any(
            keyword in line_lower
            for keyword in SUSPICIOUS_SYSMON_KEYWORDS
        ):
            interesting_lines.append(line)

        if len(interesting_lines) >= max_lines:
            break

    if not interesting_lines:
        interesting_lines = lines[:max_lines]

    parsed_content = "\n".join(interesting_lines)

    risk_score, indicators = calculate_risk_score(parsed_content)

    return {
        "log_type": "sysmon",
        "total_lines": len(lines),
        "selected_lines": len(interesting_lines),
        "risk_score": risk_score,
        "indicators": indicators,
        "content": parsed_content,
    }


def prepare_log_for_ai(content: str) -> dict:
    log_type = detect_log_type(content)

    if log_type == "sysmon":
        return parse_sysmon_log(content)

    lines = content.splitlines()
    selected_lines = lines[:200]

    risk_score, indicators = calculate_risk_score(content)

    return {
        "log_type": log_type,
        "total_lines": len(lines),
        "selected_lines": len(selected_lines),
        "risk_score": risk_score,
        "indicators": indicators,
        "content": "\n".join(selected_lines),
    }