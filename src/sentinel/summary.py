from collections import Counter
from pathlib import Path


def write_markdown_summary(path, findings, decision, sources=None):
    counts = Counter(f.severity for f in findings)
    lines = [
        "# Sentinel Security Gate",
        "",
        f"**Decision:** `{decision['decision']}`",
        f"**Max risk score:** `{decision.get('max_risk_score', 0)}`",
        "",
        "## Findings",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {sev.title()} | {counts.get(sev, 0)} |")
    if sources:
        lines.extend(["", "## Scanner ingestion", "", "| Scanner | Findings |", "|---|---:|"])
        for source in sources:
            lines.append(f"| {source['scanner']} | {source['findings']} |")
    if decision.get("reasons"):
        lines.extend(["", "## Policy reasons", ""])
        lines.extend(f"- {r}" for r in decision["reasons"])
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
