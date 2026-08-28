# Sentinel Pipeline

**AI-assisted DevSecOps Security Orchestration, Correlation, Policy Gating & Remediation**

Sentinel Pipeline is a vendor-neutral security engineering platform that normalizes findings from multiple scanners, correlates duplicate risks, applies deterministic security gates, and produces developer-friendly remediation output.

[![Sentinel Security Gate](https://github.com/tejamaguluri08-cyber/sentinel-pipeline/actions/workflows/security.yml/badge.svg)](https://github.com/tejamaguluri08-cyber/sentinel-pipeline/actions/workflows/security.yml)

## v0.2 capabilities

- Semgrep adapter for SAST
- Trivy adapter for container and dependency findings
- Gitleaks adapter for secrets
- Checkov adapter for IaC
- normalized vulnerability schema
- cross-scanner correlation
- risk scoring
- deterministic policy gates
- SARIF output
- HTML and JSON reports
- GitHub Actions security workflow
- AI-ready remediation context

## Architecture

```text
Source / Pull Request
        |
        v
+-----------------------------+
| Security Scanners           |
| Semgrep | Trivy | Gitleaks  |
| Checkov                     |
+-------------+---------------+
              |
              v
+-----------------------------+
| Scanner Adapter Layer       |
+-------------+---------------+
              |
              v
+-----------------------------+
| Finding Normalization       |
+-------------+---------------+
              |
              v
+-----------------------------+
| Correlation + Risk Scoring  |
+-------------+---------------+
              |
              v
+-----------------------------+
| Deterministic Policy Gate   |
+----------+----------+-------+
           |          |
         PASS       BLOCK
           |
           v
+-----------------------------+
| SARIF | HTML | JSON         |
| AI Remediation Context      |
+-----------------------------+
```

## Run locally

```powershell
pip install -r requirements.txt
$env:PYTHONPATH="src"
python -m sentinel scan --input sample_data/findings.json --output reports
```

## Parse native scanner output

```powershell
python -m sentinel scan --adapter trivy --input trivy.json --output reports
python -m sentinel scan --adapter semgrep --input semgrep.json --output reports
python -m sentinel scan --adapter gitleaks --input gitleaks.json --output reports
python -m sentinel scan --adapter checkov --input checkov.json --output reports
```

## Outputs

```text
reports/
  findings-normalized.json
  correlated-findings.json
  policy-decision.json
  sentinel.sarif
  security-report.html
```

## Design principle

AI may explain findings and recommend remediation, but AI does **not** decide whether a build passes. Enforcement stays deterministic, explicit, and auditable.

## Portfolio disclaimer

This is an original portfolio implementation using synthetic sample data and public scanner formats. It contains no employer source code, internal URLs, credentials, confidential vulnerability data, or proprietary configurations.

## Roadmap

- OPA/Rego policy-as-code
- CycloneDX SBOM ingestion
- EPSS + CISA KEV enrichment
- GitHub pull-request annotations
- Azure DevOps adapter
- FastAPI service
- dashboard UI
- optional LLM provider integration

## License

MIT
