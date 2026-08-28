import json
LEVEL={"critical":"error","high":"error","medium":"warning","low":"note","info":"note"}
def write_sarif(path, findings):
    results=[]
    for i,f in enumerate(findings):
        results.append({"ruleId":f"{f.scanner}:{f.finding_type}:{i}","level":LEVEL.get(f.severity,"note"),
                        "message":{"text":f.description or f.title},
                        "locations":[{"physicalLocation":{"artifactLocation":{"uri":f.asset}}}],
                        "properties":{"scanner":f.scanner,"findingType":f.finding_type,"riskScore":f.risk_score,
                                      "cve":f.cve,"cwe":f.cwe}})
    payload={"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json",
             "runs":[{"tool":{"driver":{"name":"Sentinel Pipeline","version":"0.2.0"}},"results":results}]}
    path.write_text(json.dumps(payload,indent=2),encoding="utf-8")
