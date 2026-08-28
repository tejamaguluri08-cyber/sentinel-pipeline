import json
from sentinel.normalize import normalize
from sentinel.enrichment import enrich_findings
from sentinel.merge import load_scanner_directory
from sentinel.sbom import requirements_to_cyclonedx


def test_kev_enrichment_increases_score():
    finding = normalize({"scanner":"trivy","type":"sca","title":"x","severity":"high","asset":"requirements.txt","cve":"CVE-1"})
    out = enrich_findings([finding], {"CVE-1": {"epss": 0.9, "kev": True}})[0]
    assert out["kev"] is True
    assert out["enriched_risk_score"] == 100


def test_scanner_directory_is_tolerant_of_missing_files(tmp_path):
    (tmp_path / "gitleaks.json").write_text("[]", encoding="utf-8")
    raw, sources = load_scanner_directory(tmp_path)
    assert raw == []
    assert sources[0]["scanner"] == "gitleaks"


def test_cyclonedx_generation(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("PyYAML==6.0.2\nJinja2>=3.1\n", encoding="utf-8")
    out = tmp_path / "sbom.json"
    payload = requirements_to_cyclonedx(req, out)
    assert payload["bomFormat"] == "CycloneDX"
    assert len(payload["components"]) == 2
    assert json.loads(out.read_text())["specVersion"] == "1.5"
