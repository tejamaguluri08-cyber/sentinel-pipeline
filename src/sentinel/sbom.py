from pathlib import Path
import json
import re

REQ = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|>|<)?\s*([^;#\s]+)?")


def requirements_to_cyclonedx(requirements_path, output_path):
    components = []
    p = Path(requirements_path)
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = REQ.match(line)
            if not m:
                continue
            name, version = m.group(1), m.group(2)
            comp = {"type": "library", "name": name, "purl": f"pkg:pypi/{name.lower()}"}
            if version and version not in {"*", ""}:
                comp["version"] = version
                comp["purl"] += f"@{version}"
            components.append(comp)
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "sentinel-pipeline", "version": "0.3.0"}},
        "components": components,
    }
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload
