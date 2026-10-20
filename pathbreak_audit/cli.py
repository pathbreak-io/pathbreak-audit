"""pathbreak-audit command line entry point."""
import argparse
import json
import os
import sys


def _want_color(args):
    if getattr(args, "no_color", False) or os.environ.get("NO_COLOR"):
        return False
    if args.out or args.format == "json":
        return False
    return sys.stdout.isatty()

from . import __version__
from .catalogue import load_checks
from .evaluate import evaluate, summarize, is_admin, is_default_role
from . import report

_DEMO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "demo.json")


def _load_demo():
    with open(_DEMO, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("account"), data.get("principals") or []


def build_parser():
    p = argparse.ArgumentParser(
        prog="pathbreak-audit",
        description="See the abusable IAM permissions your principals hold, so you can "
                    "tighten them before an attacker does. Read-only, single account, "
                    "point in time. From the team behind Pathbreak (https://pathbreak.io).")
    p.add_argument("--demo", action="store_true",
                   help="run against a bundled example account, no AWS credentials needed")
    p.add_argument("--profile", help="AWS profile to use (from ~/.aws)")
    p.add_argument("--region", help="AWS region (IAM is global, so this is optional)")
    p.add_argument("--format", choices=["text", "json"], default="text", help="output format")
    p.add_argument("--out", help="write the report to a file instead of stdout")
    p.add_argument("--principal", metavar="SUBSTR",
                   help="only report principals whose name contains this text")
    p.add_argument("--include-admins", action="store_true",
                   help="include principals that already hold full admin (*) (excluded by "
                        "default: they trip every check and are admin by design)")
    p.add_argument("--include-default-roles", action="store_true",
                   help="include AWS default roles: service-linked, SSO reserved, Control "
                        "Tower, Organizations, StackSets (excluded by default as noise)")
    p.add_argument("--include-access", action="store_true",
                   help="also show broad access findings: read all secrets or data, invoke any Lambda, "
                        "assume any role, open any SSM session. Off by default to avoid alert fatigue, "
                        "since reading or invoking one resource is intended. What actually reaches your "
                        "sensitive data is Pathbreak's job.")
    p.add_argument("--exit-code", action="store_true",
                   help="exit non-zero when any abusable permissions are found (for CI)")
    p.add_argument("--no-color", action="store_true",
                   help="disable colour (also respects NO_COLOR and non-TTY output)")
    p.add_argument("--version", action="version", version="pathbreak-audit " + __version__)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    _meta, checks = load_checks()

    # The clean default is the actions that are abusable no matter the target: escalation,
    # persistence, logging tampering, destruction. Context-dependent actions (reads, Lambda
    # invoke, AssumeRole, SSM sessions) only matter if the target is privileged, which the
    # CLI cannot know, so they are hidden by default to avoid alert fatigue. --include-access
    # brings them back, but only where the principal can do them to everything (Resource "*"):
    # read all secrets, invoke any function, assume any role. Reading or invoking one resource
    # is intended, so it is never flagged. Which paths actually reach data is Pathbreak's job.
    CONTEXT_TACTICS = frozenset({"collection", "exfiltration", "credential-access",
                                 "execution", "lateral-movement"})
    if args.include_access:
        star_tactics = CONTEXT_TACTICS
        context_hidden = False
    else:
        checks = [c for c in checks if c.get("tactic") not in CONTEXT_TACTICS]
        star_tactics = frozenset()
        context_hidden = True

    default_roles_skipped = 0
    if args.demo:
        account, principals = _load_demo()
    else:
        try:
            from .collect import collect, CollectionError  # noqa: F401
        except ImportError as e:  # pragma: no cover
            sys.stderr.write("pathbreak-audit: %s\n" % e)
            return 2
        try:
            account, principals, default_roles_skipped = collect(
                profile=args.profile, region=args.region,
                include_default_roles=args.include_default_roles)
        except Exception as e:  # noqa: BLE001
            sys.stderr.write("pathbreak-audit: %s\n" % e)
            return 2

    if args.principal:
        needle = args.principal.lower()
        principals = [p for p in principals if needle in (p.get("name") or "").lower()]

    # Exclude AWS default roles (catches the demo set and anything the collector missed)
    # and admins, each with a flag to include. Default roles first, then admins.
    if not args.include_default_roles:
        dflt = [p for p in principals if is_default_role(p)]
        default_roles_skipped += len(dflt)
        principals = [p for p in principals if not is_default_role(p)]
    admins_skipped = 0
    if not args.include_admins:
        admins_skipped = sum(1 for p in principals if is_admin(p))
        principals = [p for p in principals if not is_admin(p)]

    findings = evaluate(principals, checks, star_tactics=star_tactics)
    summary = summarize(principals, findings)

    if args.format == "json":
        text = report.to_json(principals, findings, summary, account=account)
    else:
        text = report.to_text(principals, findings, summary, account=account,
                              context_hidden=context_hidden, admins_skipped=admins_skipped,
                              default_roles_skipped=default_roles_skipped, color=_want_color(args))

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        sys.stderr.write("pathbreak-audit: wrote %s\n" % args.out)
    else:
        sys.stdout.write(text)

    if args.exit_code and findings:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
