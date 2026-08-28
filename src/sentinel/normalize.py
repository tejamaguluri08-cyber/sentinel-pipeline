from sentinel.models import Finding

SEVERITY_SCORE = {
    "critical": 100,
    "high": 80,
    "medium": 50,
    "low": 20,
    "info": 5,
}

TYPE_BONUS = {
    "secret": 10,
    "sast": 5,
    "sca": 5,
    "iac": 5,
    "container": 5,
}

def normalize(raw: dict) -> Finding:
    severity = str(raw.get("severity", "info")).lower()
    finding_type = raw.get("type", "unknown")
    base = SEVERITY_SCORE.get(severity, 5)
    score = min(100, base + TYPE_BONUS.get(finding_type, 0))

    return Finding(
        scanner=raw.get("scanner", "unknown"),
        finding_type=finding_type,
        title=raw.get("title", "Untitled finding"),
        severity=severity,
        asset=raw.get("asset", "unknown"),
        description=raw.get("description", ""),
        cve=raw.get("cve"),
        cwe=raw.get("cwe"),
        risk_score=score,
    )
