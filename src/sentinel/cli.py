import argparse
import json
from pathlib import Path

from sentinel.normalize import normalize
from sentinel.policy import load_policy, evaluate
from sentinel.remediation import remediation_guidance, build_ai_prompt
from sentinel.report import write_json, write_html

def run_scan(input_path: str, output_dir: str, policy_path: str) -> int:
    with open(input_path, "r", encoding="utf-8") as f:
        raw_findings = json.load(f)

    findings = [normalize(item) for item in raw_findings]
    policy = load_policy(policy_path)
    decision = evaluate(findings, policy)

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    normalized = []
    for f in findings:
        item = f.to_dict()
        item["remediation"] = remediation_guidance(f)
        item["ai_prompt"] = build_ai_prompt(f)
        normalized.append(item)

    write_json(output / "findings-normalized.json", normalized)
    write_json(output / "policy-decision.json", decision)
    write_html("templates", output / "security-report.html", normalized, decision)

    print(json.dumps(decision, indent=2))
    return 2 if decision["decision"] == "BLOCK" else 0

def main():
    parser = argparse.ArgumentParser(prog="sentinel")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Normalize findings and evaluate the security gate")
    scan.add_argument("--input", required=True)
    scan.add_argument("--output", default="reports")
    scan.add_argument("--policy", default="policy/default-policy.yml")

    args = parser.parse_args()

    if args.command == "scan":
        return run_scan(args.input, args.output, args.policy)

    return 1
