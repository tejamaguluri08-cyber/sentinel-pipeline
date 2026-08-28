import json
from sentinel.adapters.semgrep import SemgrepAdapter
from sentinel.adapters.trivy import TrivyAdapter
def test_semgrep(tmp_path):
    p=tmp_path/"s.json"; p.write_text(json.dumps({"results":[{"path":"app.py","extra":{"message":"Injection","severity":"ERROR","metadata":{"cwe":["CWE-89"]}}}]}))
    assert SemgrepAdapter().parse(p)[0]["type"]=="sast"
def test_trivy(tmp_path):
    p=tmp_path/"t.json"; p.write_text(json.dumps({"Results":[{"Target":"image","Class":"os-pkgs","Vulnerabilities":[{"VulnerabilityID":"CVE-DEMO","Severity":"CRITICAL"}]}]}))
    assert TrivyAdapter().parse(p)[0]["type"]=="container"
