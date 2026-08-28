import json
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

def write_json(path: Path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

def write_html(template_dir: str, output_path: Path, findings, decision):
    env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)
    template = env.get_template("report.html.j2")
    html = template.render(findings=findings, decision=decision)
    output_path.write_text(html, encoding="utf-8")
