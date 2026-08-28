# Sentinel Pipeline

**AI-assisted DevSecOps Security Orchestration & Remediation Platform**

Sentinel Pipeline is a portfolio-grade security engineering project that demonstrates how modern CI/CD security controls can be orchestrated, normalized, policy-gated, and summarized into actionable remediation guidance.

## What it does

- Scans repositories for:
  - SAST
  - SCA / dependency risks
  - secrets
  - IaC issues
  - container risks
- Normalizes findings into one schema
- Assigns risk scores
- Applies deterministic policy gates
- Produces JSON and HTML reports
- Generates AI-ready remediation prompts without allowing AI to make enforcement decisions
- Runs locally, in Docker, and in GitHub Actions

## Architecture

```text
              ┌─────────────────────┐
              │   Source Repository │
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │ Scanner Orchestrator│
              └──────────┬──────────┘
                         │
       ┌─────────────────┼──────────────────┐
       ▼                 ▼                  ▼
   SAST/SCA          Secrets/IaC       Container
       └─────────────────┼──────────────────┘
                         ▼
              ┌─────────────────────┐
              │ Finding Normalizer  │
              └──────────┬──────────┘
                         ▼
              ┌─────────────────────┐
              │ Risk Scoring Engine │
              └──────────┬──────────┘
                         ▼
              ┌─────────────────────┐
              │ Policy Gate Engine  │
              └──────┬────────┬─────┘
                     │        │
                  PASS      BLOCK
                     │        │
                     └───┬────┘
                         ▼
              ┌─────────────────────┐
              │ Reports + Guidance  │
              └─────────────────────┘
```

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m sentinel scan --input sample_data/findings.json --output reports
```

## Example

```bash
python -m sentinel scan --input sample_data/findings.json --output reports
```

The command produces:

- `reports/findings-normalized.json`
- `reports/security-report.html`
- `reports/policy-decision.json`

## Policy model

The default policy blocks builds when:

- a `critical` finding exists, or
- two or more `high` findings exist.

You can customize this in `policy/default-policy.yml`.

## Why AI is not the enforcement engine

Security gates should remain deterministic and auditable. Sentinel Pipeline uses AI only for explanation and remediation assistance. Policy decisions are made by explicit rules.

## Portfolio focus

This repository uses synthetic sample data and open-source tooling patterns only. It contains no employer code, credentials, URLs, proprietary configurations, or production data.

## Roadmap

- Native SARIF ingestion
- Trivy/Semgrep/Gitleaks adapters
- OPA/Rego policy support
- FastAPI dashboard
- GitHub PR annotations
- Azure DevOps pipeline adapter
- SBOM ingestion
- EPSS/KEV enrichment
- Optional LLM remediation provider

## License

MIT
