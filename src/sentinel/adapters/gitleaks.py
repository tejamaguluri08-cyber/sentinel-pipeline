import json
from .base import ScannerAdapter
class GitleaksAdapter(ScannerAdapter):
    def parse(self, path):
        return [{"scanner":"gitleaks","type":"secret","title":x.get("Description","Secret detected"),
                 "severity":"high","asset":x.get("File","unknown"),
                 "description":"Rule: "+x.get("RuleID","unknown")}
                for x in json.loads(path.read_text(encoding="utf-8"))]
