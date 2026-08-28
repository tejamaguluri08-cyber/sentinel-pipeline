from collections import defaultdict
def correlate(findings):
    groups=defaultdict(list)
    for f in findings:
        groups[f.cve or f.cwe or f"{f.asset}:{f.title}".lower()].append(f)
    out=[]
    for k,items in groups.items():
        out.append({"key":k,"count":len(items),"scanners":sorted(set(i.scanner for i in items)),
                    "assets":sorted(set(i.asset for i in items)),
                    "max_risk_score":max(i.risk_score for i in items),
                    "severity":max(items,key=lambda x:x.risk_score).severity,
                    "title":items[0].title})
    return sorted(out,key=lambda x:x["max_risk_score"],reverse=True)
