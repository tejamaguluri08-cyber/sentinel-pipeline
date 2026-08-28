from .semgrep import SemgrepAdapter
from .trivy import TrivyAdapter
from .gitleaks import GitleaksAdapter
from .checkov import CheckovAdapter

ADAPTERS = {
    "semgrep": SemgrepAdapter(),
    "trivy": TrivyAdapter(),
    "gitleaks": GitleaksAdapter(),
    "checkov": CheckovAdapter(),
}
