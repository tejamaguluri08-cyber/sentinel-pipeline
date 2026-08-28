# Sentinel Pipeline v0.2 Upgrade

This upgrade adds real scanner-adapter architecture and enterprise-style security correlation.

## New capabilities
- Semgrep native JSON adapter
- Trivy native JSON adapter
- Gitleaks native JSON adapter
- Checkov native JSON adapter
- vulnerability correlation engine
- SARIF generation for GitHub security ecosystems
- expanded GitHub Actions security workflow
- automated unit tests

## Security architecture
`Scanner -> Adapter -> Normalizer -> Correlation -> Risk -> Policy Gate -> SARIF/HTML/JSON -> AI remediation context`

## Important design decision
AI assists with explanation and remediation. Deterministic policy remains the enforcement authority.

## Next milestone
v0.3 will add OPA/Rego policies, CycloneDX SBOM ingestion, EPSS/CISA KEV enrichment, GitHub PR comments, Azure DevOps adapter, FastAPI, and a security dashboard.
