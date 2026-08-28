from collections import Counter
import yaml


def load_policy(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def evaluate(findings, policy: dict, enriched=None) -> dict:
    counts = Counter(f.severity for f in findings)
    block_on = policy.get("block_on", {})
    min_score = int(policy.get("minimum_risk_score_to_block", 101))
    reasons = []

    critical_limit = int(block_on.get("critical_count", 999999))
    high_limit = int(block_on.get("high_count", 999999))
    kev_limit = int(block_on.get("kev_count", 999999))
    epss_threshold = float(block_on.get("epss_threshold", 2.0))

    if counts.get("critical", 0) >= critical_limit:
        reasons.append(f"Critical finding threshold reached: {counts.get('critical', 0)} >= {critical_limit}")
    if counts.get("high", 0) >= high_limit:
        reasons.append(f"High finding threshold reached: {counts.get('high', 0)} >= {high_limit}")

    scored = [f for f in findings if f.risk_score >= min_score]
    if scored:
        reasons.append(f"{len(scored)} finding(s) have risk score >= {min_score}")

    if enriched:
        kev_count = sum(1 for x in enriched if x.get("kev"))
        if kev_count >= kev_limit:
            reasons.append(f"Known Exploited Vulnerability threshold reached: {kev_count} >= {kev_limit}")
        high_epss = [x for x in enriched if float(x.get("epss", 0)) >= epss_threshold]
        if high_epss:
            reasons.append(f"{len(high_epss)} finding(s) have EPSS >= {epss_threshold}")

    return {
        "decision": "BLOCK" if reasons else "PASS",
        "reasons": reasons,
        "counts": dict(counts),
        "max_risk_score": max((f.risk_score for f in findings), default=0),
    }
