package sentinel.security

default allow := true

critical_findings := [f | f := input.findings[_]; lower(f.severity) == "critical"]
kev_findings := [f | f := input.findings[_]; f.kev == true]

deny contains msg if {
  count(critical_findings) > 0
  msg := sprintf("%d critical finding(s) detected", [count(critical_findings)])
}

deny contains msg if {
  count(kev_findings) > 0
  msg := sprintf("%d CISA KEV finding(s) detected", [count(kev_findings)])
}

allow if count(deny) == 0
