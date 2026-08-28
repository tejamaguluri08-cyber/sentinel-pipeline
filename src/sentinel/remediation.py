def remediation_guidance(finding) -> str:
    if finding.finding_type == "sast" and finding.cwe == "CWE-89":
        return (
            "Use parameterized queries or prepared statements. "
            "Avoid string concatenation for SQL commands and validate input."
        )
    if finding.finding_type == "secret":
        return (
            "Revoke the exposed credential, remove it from source history, "
            "and store replacement credentials in an approved secret manager."
        )
    if finding.finding_type == "sca":
        return (
            "Validate exploitability, upgrade to a fixed version, regenerate the lockfile, "
            "and re-run dependency and regression tests."
        )
    return "Review the finding, validate exploitability, remediate, and re-run the security gate."

def build_ai_prompt(finding) -> str:
    return (
        "You are assisting a security engineer. Explain this finding and propose a concise "
        "developer remediation plan. Do not make policy decisions.\n\n"
        f"Title: {finding.title}\n"
        f"Type: {finding.finding_type}\n"
        f"Severity: {finding.severity}\n"
        f"Asset: {finding.asset}\n"
        f"Description: {finding.description}\n"
        f"CVE: {finding.cve or 'N/A'}\n"
        f"CWE: {finding.cwe or 'N/A'}\n"
    )
