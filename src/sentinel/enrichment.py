import json
from pathlib import Path


def load_threat_intel(path=None):
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    data = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return {str(x.get("cve", "")).upper(): x for x in data if x.get("cve")}
    return {str(k).upper(): v for k, v in data.items()}


def enrich_findings(findings, intel):
    enriched = []
    for finding in findings:
        item = finding.to_dict()
        record = intel.get((finding.cve or "").upper(), {}) if finding.cve else {}
        epss = float(record.get("epss", 0) or 0)
        kev = bool(record.get("kev", False))
        bonus = (15 if kev else 0) + (10 if epss >= 0.5 else 5 if epss >= 0.1 else 0)
        item["epss"] = epss
        item["kev"] = kev
        item["base_risk_score"] = finding.risk_score
        item["enriched_risk_score"] = min(100, finding.risk_score + bonus)
        item["threat_intel_source"] = record.get("source", "local-demo") if record else None
        enriched.append(item)
    return enriched
