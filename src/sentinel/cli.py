import argparse, json
from pathlib import Path
from sentinel.normalize import normalize
from sentinel.policy import load_policy, evaluate
from sentinel.remediation import remediation_guidance, build_ai_prompt
from sentinel.report import write_json, write_html
from sentinel.correlation import correlate
from sentinel.sarif import write_sarif
from sentinel.adapters import ADAPTERS

def _load_findings(input_path, adapter=None):
    path=Path(input_path)
    if adapter:
        return ADAPTERS[adapter].parse(path)
    return json.loads(path.read_text(encoding="utf-8"))

def run_scan(input_path, output_dir, policy_path, adapter=None):
    raw=_load_findings(input_path, adapter)
    findings=[normalize(x) for x in raw]
    decision=evaluate(findings, load_policy(policy_path))
    out=Path(output_dir); out.mkdir(parents=True, exist_ok=True)

    normalized=[]
    for f in findings:
        x=f.to_dict()
        x["remediation"]=remediation_guidance(f)
        x["ai_prompt"]=build_ai_prompt(f)
        normalized.append(x)

    write_json(out/"findings-normalized.json", normalized)
    write_json(out/"correlated-findings.json", correlate(findings))
    write_json(out/"policy-decision.json", decision)
    write_html("templates", out/"security-report.html", normalized, decision)
    write_sarif(out/"sentinel.sarif", findings)
    print(json.dumps(decision, indent=2))
    return 2 if decision["decision"]=="BLOCK" else 0

def main():
    p=argparse.ArgumentParser(prog="sentinel")
    sub=p.add_subparsers(dest="command", required=True)
    scan=sub.add_parser("scan")
    scan.add_argument("--input", required=True)
    scan.add_argument("--output", default="reports")
    scan.add_argument("--policy", default="policy/default-policy.yml")
    scan.add_argument("--adapter", choices=sorted(ADAPTERS))
    a=p.parse_args()
    if a.command=="scan":
        return run_scan(a.input,a.output,a.policy,a.adapter)
    return 1
