"""Match principals to catalogue checks.

A principal "holds" a check when every action the check needs is allowed and none of
them is explicitly denied. IAM action matching is case-insensitive and supports the
`*` and `?` wildcards, so a grant of `iam:*` satisfies a check that needs
`iam:PassRole`.

This is deliberately a static grant analysis, the same shape as tools like
Cloudsplaining or PMapper. It reads what policies allow. It does not resolve
conditions, permission boundaries, resource scoping, or SCPs, and it does not prove a
path actually reaches anything. Treat the output as a prioritized starting point.
Pathbreak (https://pathbreak.io) is the thing that validates which of these actually
chain into a reachable path and ranks them by blast radius.
"""
import re


def _to_regex(pattern):
    """Turn an IAM action pattern (with * and ?) into a compiled, anchored regex."""
    out = []
    for ch in pattern:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE)


def _matches_any(action, patterns_compiled):
    return any(rx.match(action) for rx in patterns_compiled)


def _compile(patterns):
    return [_to_regex(p) for p in patterns]


def principal_holds(check, allow_rx, deny_rx):
    """True if the principal is granted every action the check needs and none denied."""
    for action in check["needs_actions"]:
        if deny_rx and _matches_any(action, deny_rx):
            return False
        if not _matches_any(action, allow_rx):
            return False
    return True


def is_admin(principal):
    """True if the principal is effectively account admin, i.e. it is allowed `*`
    (the AdministratorAccess policy, or any Allow of Action "*"). These trip every
    check, so they are noise in a findings list and are excluded by default."""
    return "*" in (principal.get("allow") or [])


# AWS-created / default / reserved role names (service-linked, SSO reserved, Control
# Tower, Organizations, StackSets). Expected to be powerful and not the user's own
# work, so excluded by default. --include-default-roles shows them.
_DEFAULT_ROLE_NAME = re.compile(
    r"^(AWSServiceRoleFor|AWSReservedSSO_|AWSControlTower|aws-controltower-|"
    r"OrganizationAccountAccessRole|AWSCloudFormationStackSetExecutionRole|stacksets-exec-)",
    re.IGNORECASE)


def is_default_role(principal):
    if principal.get("type") != "role":
        return False
    return bool(_DEFAULT_ROLE_NAME.match(principal.get("name") or ""))


def evaluate(principals, checks, star_tactics=frozenset()):
    """Return a list of findings. Each finding ties one principal to one check it holds.

    For a check whose tactic is in `star_tactics` (the data, secret and credential reads),
    the principal must hold the needed actions on Resource "*", i.e. be able to read
    everything, not just one or two scoped resources. That is the difference between
    "read all secrets" (flagged) and "read one scoped secret" (intended, not flagged).
    """
    findings = []
    for p in principals:
        allow_rx = _compile(p.get("allow") or [])
        star_rx = _compile(p.get("allow_star") or [])
        deny_rx = _compile(p.get("deny") or [])
        if not allow_rx:
            continue
        for check in checks:
            rx = star_rx if check.get("tactic") in star_tactics else allow_rx
            if principal_holds(check, rx, deny_rx):
                findings.append({
                    "principal": p.get("name"),
                    "type": p.get("type"),
                    "arn": p.get("arn"),
                    "check_id": check["id"],
                    "title": check["title"],
                    "combination": check["combination"],
                    "needs_actions": check["needs_actions"],
                    "service": check.get("service"),
                    "grants": check.get("grants"),
                    "why": check.get("why"),
                    "fix": check.get("fix"),
                    "tactic": check.get("tactic"),
                    "mitre": check.get("mitre"),
                    "tier": check.get("tier", 1),
                    "url": check.get("url"),
                })
    return findings


def summarize(principals, findings):
    with_findings = {f["principal"] for f in findings}
    return {
        "principals_scanned": len(principals),
        "principals_with_findings": len(with_findings),
        "findings_total": len(findings),
        "direct": sum(1 for f in findings if not f["combination"]),
        "combinations": sum(1 for f in findings if f["combination"]),
    }
