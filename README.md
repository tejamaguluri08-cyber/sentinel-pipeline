# Sentinel Pipeline

**AI-assisted DevSecOps Security Orchestration, Risk Enrichment & Remediation Platform**

Sentinel Pipeline is a portfolio-grade security engineering project showing how multiple CI/CD security scanners can be normalized into one risk model, correlated, enriched with exploit intelligence, policy-gated, exported to SARIF, and converted into actionable remediation guidance.

## v0.3 capabilities

- Native adapters for **Semgrep (SAST)**, **Trivy (SCA/container)**, **Gitleaks (secrets)**, and **Checkov (IaC)**
- Multi-scanner ingestion and normalization into one finding schema
- Cross-scanner correlation and deduplication signals
- Deterministic risk scoring and YAML policy gates
- Optional **EPSS / KEV-style threat-intelligence enrichment** using local JSON
- **CycloneDX 1.5 SBOM** generation
- **SARIF 2.1.0** output for GitHub-compatible security results
- HTML, JSON, and Markdown job summaries
- AI-ready remediation prompts; **AI never makes enforcement decisions**
- OPA/Rego reference policy for policy-as-code evolution
- GitHub Actions automation and unit tests

## Architecture

```text
Semgrep ─┐
Trivy   ─┼─> Adapters -> Normalizer -> Correlation -> Threat Intel -> Risk/Policy
Gitleaks─┤                                                        |       |
Checkov ─┘                                                        |    PASS/BLOCK
                                                                  v
                                              JSON / HTML / SARIF / SBOM / AI context
```

## Quick start

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
pip install -r requirements.txt
$env:PYTHONPATH="src"  # PowerShell
pytest -q
python -m sentinel scan --input sample_data/findings.json --output reports
```

The sample data intentionally contains blocking findings, so the demo `scan` command may return exit code `2` while still generating reports.

## Multi-scanner mode

Place native scanner exports in a directory with these names:

```text
scanner-results/
  semgrep.json
  trivy.json
  gitleaks.json
  checkov.json
```

Then run:

```bash
python -m sentinel merge --scanner-dir scanner-results --output reports --threat-intel threat_intel/demo.json
```

Missing scanner files are allowed; Sentinel ingests whichever exports exist.

## Generate an SBOM

```bash
python -m sentinel sbom --requirements requirements.txt --output reports/sbom.cdx.json
```

## Policy model

`policy/default-policy.yml` can block on:

- critical finding count
- high finding count
- KEV-tagged finding count
- EPSS threshold
- minimum base risk score

`policy/rego/security_gate.rego` is a reference OPA/Rego policy showing how the gate can evolve into enterprise policy-as-code.

## Security design principle

LLMs are intentionally outside the enforcement path. Sentinel can generate AI-ready remediation context, but build decisions remain deterministic, auditable, and policy-driven.

## Portfolio safety

This repository uses synthetic/sample data and open-source tooling patterns only. Do not commit employer code, internal URLs, credentials, proprietary configurations, or confidential vulnerability exports.

## Roadmap

- GitHub pull-request comments and branch protection integration
- Live EPSS and CISA KEV refresh job
- Azure DevOps adapter and pipeline checks
- OPA CLI enforcement
- FastAPI/dashboard
- VEX support and SBOM diffing
- Optional LLM provider for remediation explanations

## License

MIT
