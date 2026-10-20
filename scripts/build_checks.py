#!/usr/bin/env python3
"""Generate pathbreak_audit/data/checks.json from the Pathbreak dangerous-permissions
catalogue (the same source behind https://pathbreak.io/aws-privilege-escalation-map).

Public fields only. Engine internals (raw weight, confidence, vet_guidance, last_checked)
are not shipped. Weight is reduced to a coarse 1 to 3 tier used only for ordering.

Maintainer tool. Run it when the catalogue changes:
    python3 scripts/build_checks.py path/to/attack_primitives.yaml
"""
import sys, os, re, json, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SRC = os.path.join(HERE, "attack_primitives.yaml")
OUT = os.path.join(HERE, "..", "pathbreak_audit", "data", "checks.json")

# Only AWS documentation and MITRE ATT&CK references ship (no third-party/vendor links).
def ref_ok(u):
    u = (u or "").lower()
    return ("aws.amazon.com" in u or "amazonaws.com" in u or "attack.mitre.org" in u)

SERVICE_NAMES = {
    "sts": "STS", "iam": "IAM", "ec2": "EC2", "s3": "S3", "kms": "KMS",
    "lambda": "Lambda", "cloudformation": "CloudFormation", "codebuild": "CodeBuild",
    "apprunner": "App Runner", "glue": "Glue", "sagemaker": "SageMaker",
    "bedrock-agentcore": "Bedrock AgentCore", "batch": "Batch", "codedeploy": "CodeDeploy",
    "states": "Step Functions", "ssm": "Systems Manager",
    "ec2-instance-connect": "EC2 Instance Connect", "sso": "IAM Identity Center",
    "eks": "EKS", "ecs": "ECS", "secretsmanager": "Secrets Manager", "dynamodb": "DynamoDB",
    "ecr": "ECR", "logs": "CloudWatch Logs", "redshift": "Redshift", "rds-db": "RDS",
    "rds": "RDS", "ebs": "EBS", "cloudtrail": "CloudTrail", "guardduty": "GuardDuty",
    "config": "Config", "securityhub": "Security Hub", "access-analyzer": "Access Analyzer",
    "cloudwatch": "CloudWatch", "wafv2": "WAF", "organizations": "Organizations",
    "lakeformation": "Lake Formation", "sns": "SNS", "sqs": "SQS", "events": "EventBridge",
}

def service_of(action):
    p = (action or "").split(":")[0]
    return SERVICE_NAMES.get(p, p.upper() if p else "")

def tier_of(weight):
    try:
        w = int(weight)
    except (TypeError, ValueError):
        w = 0
    return 3 if w >= 35 else (2 if w >= 26 else 1)

def detemplate(s):
    s = str(s or "")
    s = s.replace("{src}", "this principal").replace("{dst}", "the target")
    s = re.sub(r"\{[^}]+\}", "", s)  # drop any stray tokens
    return re.sub(r"\s+", " ", s).strip()

# Plain-language pass for the CLI wording. "Mint" reads as marketing/AI copy; "create" is
# the word AWS uses. This only affects the CLI's checks.json, not the website catalogue.
_DEAI = [
    (re.compile(r"\bMinting\b"), "Creating"), (re.compile(r"\bminting\b"), "creating"),
    (re.compile(r"\bMinted\b"), "Created"), (re.compile(r"\bminted\b"), "created"),
    (re.compile(r"\bMints\b"), "Creates"), (re.compile(r"\bmints\b"), "creates"),
    (re.compile(r"\bMint\b"), "Create"), (re.compile(r"\bmint\b"), "create"),
]
# A couple of titles put the verb last, where a blind swap would read oddly; fix those by hand.
_TITLE_FIX = {
    "Roles Anywhere profile credential mint": "Create Roles Anywhere profile credentials",
}

def deai(s, is_title=False):
    s = str(s or "")
    if is_title and s in _TITLE_FIX:
        return _TITLE_FIX[s]
    for rx, rep in _DEAI:
        s = rx.sub(rep, s)
    return s

def main():
    try:
        import yaml
    except ImportError:
        sys.exit("PyYAML is needed to rebuild checks.json: pip install pyyaml")
    src = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SRC
    data = yaml.safe_load(open(src, encoding="utf-8"))
    edges = data.get("permission_edges") or []
    checks = []
    for e in edges:
        needs = e.get("needs_actions") or ([e["primary_action"]] if e.get("primary_action") else [])
        if not needs:
            continue
        prim = e.get("primary_action") or needs[0]
        mt = e.get("mitre_technique") or None
        checks.append({
            "id": e["id"],
            "title": deai((e.get("title") or e["id"]).strip(), is_title=True),
            "needs_actions": list(needs),
            "primary_action": prim,
            "service": service_of(prim),
            "category": e.get("abuse_type") or e.get("group") or "",
            "grants": deai(detemplate(e.get("signal"))),
            "why": deai(detemplate(e.get("description"))),
            "fix": deai(detemplate(e.get("cut"))),
            "tactic": e.get("tactic") or "",
            "mitre": ({"id": mt.get("id"), "name": mt.get("name")} if isinstance(mt, dict) else None),
            "tier": tier_of(e.get("weight")),
            "combination": len(needs) > 1,
            "references": [u for u in (e.get("references") or []) if ref_ok(u)],
            "url": "https://pathbreak.io/aws-privilege-escalation-map/" + e["id"],
        })
    # worst first, then alphabetical, so the report leads with what matters most
    checks.sort(key=lambda c: (-c["tier"], c["title"].lower()))
    out = {
        "schema": 1,
        "generated": datetime.date.today().isoformat(),
        "source": "https://pathbreak.io/aws-privilege-escalation-map",
        "count": len(checks),
        "checks": checks,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
        f.write("\n")
    direct = sum(1 for c in checks if not c["combination"])
    print("wrote %s: %d checks (%d direct, %d combinations)" %
          (os.path.relpath(OUT), len(checks), direct, len(checks) - direct))

if __name__ == "__main__":
    main()
