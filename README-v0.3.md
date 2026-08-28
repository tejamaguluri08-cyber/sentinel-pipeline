# Sentinel Pipeline v0.3 Upgrade

v0.3 turns Sentinel from a single-export demo into a multi-scanner security orchestration pipeline.

## Added

- Multi-scanner ingestion from native Semgrep, Trivy, Gitleaks, and Checkov JSON
- Threat-intelligence enrichment fields for EPSS and CISA KEV-style data
- Policy rules for critical, high, KEV, and EPSS thresholds
- CycloneDX 1.5 SBOM generation
- Improved SARIF with explicit rules
- GitHub Actions job summary output
- OPA/Rego reference policy
- v0.3 unit tests

All bundled threat-intelligence data is synthetic. No employer or production data is included.
