import json
from .base import ScannerAdapter
class TrivyAdapter(ScannerAdapter):
    def parse(self, path):
        data=json.loads(path.read_text(encoding="utf-8")); out=[]
        for r in data.get("Results",[]):
            for v in r.get("Vulnerabilities") or []:
                out.append({"scanner":"trivy","type":"container" if r.get("Class")=="os-pkgs" else "sca",
                            "title":v.get("Title") or v.get("VulnerabilityID","Trivy finding"),
                            "severity":str(v.get("Severity","UNKNOWN")).lower(),"asset":r.get("Target","unknown"),
                            "cve":v.get("VulnerabilityID"),"description":v.get("Description","")})
        return out
