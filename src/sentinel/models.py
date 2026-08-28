from dataclasses import dataclass, asdict
from typing import Optional

@dataclass
class Finding:
    scanner: str
    finding_type: str
    title: str
    severity: str
    asset: str
    description: str
    cve: Optional[str] = None
    cwe: Optional[str] = None
    risk_score: int = 0

    def to_dict(self):
        return asdict(self)
