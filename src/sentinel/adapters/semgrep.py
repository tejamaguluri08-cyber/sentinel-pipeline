import json
from .base import ScannerAdapter
class SemgrepAdapter(ScannerAdapter):
    def parse(self, path):
        data=json.loads(path.read_text(encoding="utf-8")); out=[]
        for x in data.get("results",[]):
            e=x.get("extra",{}); m=e.get("metadata",{}); sev=str(e.get("severity","INFO")).lower()
            sev={"error":"high","warning":"medium","info":"low"}.get(sev,sev)
            cwe=m.get("cwe"); cwe=cwe[0] if isinstance(cwe,list) and cwe else cwe
            out.append({"scanner":"semgrep","type":"sast","title":e.get("message",x.get("check_id","Semgrep finding")),
                        "severity":sev,"asset":x.get("path","unknown"),"cwe":cwe,"description":e.get("message","")})
        return out
