import json
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def write_sarif(path, findings):
    results = []
    rules = {}
    for i, f in enumerate(findings):
        rule_id = f"{f.scanner}:{f.finding_type}:{f.cve or f.cwe or i}"
        rules[rule_id] = {
            "id": rule_id,
            "shortDescription": {"text": f.title[:200]},
            "properties": {"scanner": f.scanner, "findingType": f.finding_type},
        }
        location = {"physicalLocation": {"artifactLocation": {"uri": f.asset}}}
        results.append({
            "ruleId": rule_id,
            "level": LEVEL.get(f.severity, "note"),
            "message": {"text": f.description or f.title},
            "locations": [location],
            "properties": {
                "scanner": f.scanner,
                "findingType": f.finding_type,
                "riskScore": f.risk_score,
                "cve": f.cve,
                "cwe": f.cwe,
            },
        })
    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "Sentinel Pipeline", "version": "0.3.0", "rules": list(rules.values())}},
            "results": results,
        }],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
