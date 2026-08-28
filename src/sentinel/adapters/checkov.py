import json
from .base import ScannerAdapter
class CheckovAdapter(ScannerAdapter):
    def parse(self, path):
        data=json.loads(path.read_text(encoding="utf-8"))
        return [{"scanner":"checkov","type":"iac","title":x.get("check_name",x.get("check_id","Checkov finding")),
                 "severity":"high","asset":x.get("file_path","unknown"),
                 "description":x.get("guideline") or x.get("check_name","")}
                for x in data.get("results",{}).get("failed_checks",[])]
