from pathlib import Path
from sentinel.adapters import ADAPTERS

DEFAULT_FILES = {
    "semgrep": "semgrep.json",
    "trivy": "trivy.json",
    "gitleaks": "gitleaks.json",
    "checkov": "checkov.json",
}


def load_scanner_directory(directory):
    directory = Path(directory)
    raw, sources = [], []
    for adapter_name, filename in DEFAULT_FILES.items():
        path = directory / filename
        if not path.exists():
            continue
        parsed = ADAPTERS[adapter_name].parse(path)
        raw.extend(parsed)
        sources.append({"scanner": adapter_name, "file": str(path), "findings": len(parsed)})
    return raw, sources
