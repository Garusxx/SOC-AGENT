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

    if "sysmon" in lower or "eventid: 1" in lower or "eventid=1" in lower:
        return "sysmon"

    if "powershell" in lower:
        return "powershell"

    if "eventid: 4625" in lower or "eventid=4625" in lower:
        return "windows-security"

    return "generic"


def parse_sysmon_log(content: str, max_lines: int = 200) -> dict:
    lines = content.splitlines()

    interesting_lines = []

    for line in lines:
        line_lower = line.lower()

        if any(keyword in line_lower for keyword in SUSPICIOUS_SYSMON_KEYWORDS):
            interesting_lines.append(line)

        if len(interesting_lines) >= max_lines:
            break

    if not interesting_lines:
        interesting_lines = lines[:max_lines]

    parsed_content = "\n".join(interesting_lines)

    return {
        "log_type": "sysmon",
        "total_lines": len(lines),
        "selected_lines": len(interesting_lines),
        "content": parsed_content,
    }


def prepare_log_for_ai(content: str) -> dict:
    log_type = detect_log_type(content)

    if log_type == "sysmon":
        return parse_sysmon_log(content)

    lines = content.splitlines()
    selected_lines = lines[:200]

    return {
        "log_type": log_type,
        "total_lines": len(lines),
        "selected_lines": len(selected_lines),
        "content": "\n".join(selected_lines),
    }