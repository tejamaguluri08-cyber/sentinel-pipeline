import argparse
import json
from pathlib import Path
from sentinel.normalize import normalize
from sentinel.policy import load_policy, evaluate
from sentinel.remediation import remediation_guidance, build_ai_prompt
from sentinel.report import write_json, write_html
from sentinel.correlation import correlate
from sentinel.sarif import write_sarif
from sentinel.adapters import ADAPTERS
from sentinel.merge import load_scanner_directory
from sentinel.enrichment import load_threat_intel, enrich_findings
from sentinel.sbom import requirements_to_cyclonedx
from sentinel.summary import write_markdown_summary


def _load_findings(input_path, adapter=None):
    path = Path(input_path)
    if adapter:
        return ADAPTERS[adapter].parse(path)
    return json.loads(path.read_text(encoding="utf-8"))


def _run(raw, output_dir, policy_path, threat_intel=None, sources=None):
    findings = [normalize(x) for x in raw]
    intel = load_threat_intel(threat_intel)
    enriched = enrich_findings(findings, intel)
    decision = evaluate(findings, load_policy(policy_path), enriched=enriched)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    normalized = []
    for f in findings:
        x = f.to_dict()
        x["remediation"] = remediation_guidance(f)
        x["ai_prompt"] = build_ai_prompt(f)
        normalized.append(x)

    write_json(out / "findings-normalized.json", normalized)
    write_json(out / "findings-enriched.json", enriched)
    write_json(out / "correlated-findings.json", correlate(findings))
    write_json(out / "policy-decision.json", decision)
    if sources is not None:
        write_json(out / "scanner-ingestion.json", sources)
    write_html("templates", out / "security-report.html", normalized, decision)
    write_sarif(out / "sentinel.sarif", findings)
    write_markdown_summary(out / "job-summary.md", findings, decision, sources=sources)
    print(json.dumps(decision, indent=2))
    return 2 if decision["decision"] == "BLOCK" else 0


def run_scan(input_path, output_dir, policy_path, adapter=None, threat_intel=None):
    return _run(_load_findings(input_path, adapter), output_dir, policy_path, threat_intel)


def run_merge(scanner_dir, output_dir, policy_path, threat_intel=None):
    raw, sources = load_scanner_directory(scanner_dir)
    return _run(raw, output_dir, policy_path, threat_intel, sources=sources)


def main():
    p = argparse.ArgumentParser(prog="sentinel")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Normalize and gate one scanner export or Sentinel JSON")
    scan.add_argument("--input", required=True)
    scan.add_argument("--output", default="reports")
    scan.add_argument("--policy", default="policy/default-policy.yml")
    scan.add_argument("--adapter", choices=sorted(ADAPTERS))
    scan.add_argument("--threat-intel", default=None)

    merge = sub.add_parser("merge", help="Ingest native JSON from multiple scanners")
    merge.add_argument("--scanner-dir", required=True)
    merge.add_argument("--output", default="reports")
    merge.add_argument("--policy", default="policy/default-policy.yml")
    merge.add_argument("--threat-intel", default=None)

    sbom = sub.add_parser("sbom", help="Generate a lightweight CycloneDX SBOM from requirements.txt")
    sbom.add_argument("--requirements", default="requirements.txt")
    sbom.add_argument("--output", default="reports/sbom.cdx.json")

    a = p.parse_args()
    if a.command == "scan":
        return run_scan(a.input, a.output, a.policy, a.adapter, a.threat_intel)
    if a.command == "merge":
        return run_merge(a.scanner_dir, a.output, a.policy, a.threat_intel)
    if a.command == "sbom":
        requirements_to_cyclonedx(a.requirements, a.output)
        print(a.output)
        return 0
    return 1
