from sentinel.models import Finding
from sentinel.policy import evaluate

def test_blocks_on_critical():
    findings = [
        Finding(
            scanner="test",
            finding_type="sast",
            title="critical issue",
            severity="critical",
            asset="app.py",
            description="demo",
            risk_score=100,
        )
    ]

    policy = {
        "block_on": {"critical_count": 1, "high_count": 2},
        "minimum_risk_score_to_block": 85,
    }

    result = evaluate(findings, policy)
    assert result["decision"] == "BLOCK"
