"""Render findings as text or JSON.

The text report carries the PATHBREAK wordmark and uses the brand colours (violet to
cyan) when it is printed to a terminal. Colour is turned off automatically when the
output is piped or written to a file, so saved reports stay clean. No severity pills:
findings are ordered worst-first and labelled direct vs toxic combination, the same
taxonomy as the attack map.
"""
import json
import re
import shutil

from . import __version__

# Context-dependent tactics: only matter if the target is privileged, so they are shown
# only when granted on everything (Resource "*"). Their grant wording says "this X"; since
# they appear only when unrestricted, it reads as "any X".
_CONTEXT_TACTICS = frozenset({"collection", "exfiltration", "credential-access",
                              "execution", "lateral-movement"})

# Brand palette, matching pathbreak.io (violet to cyan). No alarm red/orange.
VIOLET = (0x8b, 0x5c, 0xf6)   # directly abusable
CYAN = (0x22, 0xd3, 0xee)     # toxic combination, and links
GREEN = (0x34, 0xd3, 0x99)    # the fix
MUTED = (0x9a, 0xa1, 0xaf)    # labels and secondary text
INK = (0xec, 0xeb, 0xf7)      # titles and counts
PATH_GRAY = (0x99, 0xa1, 0xaf)  # the brand wordmark: PATH gray, BREAK white

RESET = "\x1b[0m"


class _Style:
    def __init__(self, color):
        self.color = color

    def paint(self, text, rgb, bold=False, dim=False):
        # `dim` is intentionally ignored: the ANSI dim attribute makes an already-grey
        # label almost invisible on a dark terminal. Labels use LABEL grey instead.
        if not self.color:
            return text
        pre = "\x1b[38;2;%d;%d;%dm" % rgb
        if bold:
            pre = "\x1b[1m" + pre
        return pre + text + RESET

    def wordmark(self):
        return self.paint("PATH", PATH_GRAY, bold=True) + self.paint("BREAK", INK, bold=True)


RULE = "-" * 72


def _wrap_width(color):
    """Wrap to the real terminal width on a TTY, so a single sentence is not split on a
    wide screen. Falls back to 100 for files and pipes (colour is off there anyway)."""
    if not color:
        return 100
    try:
        return max(70, shutil.get_terminal_size().columns - 2)
    except Exception:
        return 100


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _vlen(s):
    """Visible length, ignoring ANSI colour codes (so colour never triggers a wrap)."""
    return len(_ANSI.sub("", s))


def _broad_grants(f):
    """Reword a context-tactic grant from 'this X' to 'any X'. These findings appear only
    when the principal holds the action on Resource '*', so the scope is every resource."""
    g = f.get("grants") or ""
    if f.get("tactic") in _CONTEXT_TACTICS:
        g = g.replace(" this ", " any ")
    return g


def _wrap(text, width=100, indent="      "):
    words = (text or "").split()
    lines, cur, curlen = [], indent, len(indent)
    for w in words:
        wl = _vlen(w)
        if curlen + wl + 1 > width and cur.strip():
            lines.append(cur.rstrip())
            cur, curlen = indent + w + " ", len(indent) + wl + 1
        else:
            cur += w + " "
            curlen += wl + 1
    if cur.strip():
        lines.append(cur.rstrip())
    return "\n".join(lines)


def _finding_sort_key(f):
    return (-f.get("tier", 1), 0 if f.get("combination") else 1, (f.get("title") or "").lower())


def to_text(principals, findings, summary, account=None, context_hidden=False,
            admins_skipped=0, default_roles_skipped=0, color=False):
    s = _Style(color)
    w = _wrap_width(color)
    out = []
    out.append(s.wordmark() + s.paint("   AWS IAM exposure, for defenders", MUTED))
    out.append("")
    out.append(s.paint("v" + __version__ + "   ", MUTED) + s.paint("https://pathbreak.io", CYAN))
    out.append("")

    def footer():
        out.append(s.paint(RULE, MUTED))
        out.append(s.paint("This is a point-in-time list of permissions that could be abused. To see which", MUTED))
        out.append(s.paint("of these reach your sensitive data, the blast radius across accounts, and the", MUTED))
        out.append(s.paint("one change that breaks the most paths, run Pathbreak:  ", MUTED)
                   + s.paint("https://pathbreak.io", CYAN))

    if account:
        out.append(s.paint("Account: ", MUTED) + s.paint(str(account), INK, bold=True))
    out.append("Scanned %d principal%s. %s hold abusable permissions (%s direct, %s toxic combination%s)."
               % (summary["principals_scanned"], "" if summary["principals_scanned"] == 1 else "s",
                  s.paint(str(summary["principals_with_findings"]), INK, bold=True),
                  s.paint(str(summary["direct"]), VIOLET, bold=True),
                  s.paint(str(summary["combinations"]), CYAN, bold=True),
                  "" if summary["combinations"] == 1 else "s"))
    skips = []
    if admins_skipped:
        skips.append("%d admin principal%s (already hold full access)"
                     % (admins_skipped, "" if admins_skipped == 1 else "s"))
    if default_roles_skipped:
        skips.append("%d AWS default role%s"
                     % (default_roles_skipped, "" if default_roles_skipped == 1 else "s"))
    if skips:
        out.append(s.paint("Skipped " + "; ".join(skips)
                           + ". Add --include-admins / --include-default-roles to show them.", MUTED))
    if context_hidden:
        out.append(s.paint("Hidden to avoid noise: broad reads, Lambda invoke, AssumeRole and SSM "
                           "sessions. Add --include-access for the read-all / invoke-anything cases. "
                           "Which paths reach your data is Pathbreak's job.", MUTED))
    if findings:
        out.append(s.paint('Each "to break it" line is one way to cut the path. Removing the permission '
                           "or scoping it to what the principal needs depends on your business context.", MUTED))
    out.append("")

    if not findings:
        out.append(s.paint("No principals hold any of the catalogued abusable permissions. Nice.", GREEN))
        out.append("")
        footer()
        return "\n".join(out) + "\n"

    by_principal = {}
    for f in findings:
        by_principal.setdefault((f["principal"], f["type"], f["arn"]), []).append(f)

    def principal_rank(item):
        (name, _t, _a), fs = item
        worst = max((x.get("tier", 1) for x in fs), default=1)
        return (-worst, name or "")

    for (name, ptype, arn), fs in sorted(by_principal.items(), key=principal_rank):
        out.append(s.paint(RULE, MUTED))
        out.append(s.paint((ptype or "principal").upper(), MUTED) + "  "
                   + s.paint(name or "?", INK, bold=True))
        if arn:
            out.append(s.paint("  " + arn, MUTED))
        for f in sorted(fs, key=_finding_sort_key):
            if f["combination"]:
                label = s.paint("Toxic combination of %d" % len(f["needs_actions"]), CYAN, bold=True)
            else:
                label = s.paint("Directly abusable", VIOLET, bold=True)
            out.append("  " + s.paint("*", MUTED) + " " + label
                       + s.paint("  |  ", MUTED) + s.paint(f["title"], INK))
            out.append(s.paint("      needs: ", MUTED) + " + ".join(f["needs_actions"]))
            grants = _broad_grants(f)
            if grants:
                out.append(_wrap(s.paint("grants: ", MUTED) + grants, width=w))
            if f.get("fix"):
                out.append(_wrap(s.paint("to break it: ", MUTED) + s.paint(f["fix"], GREEN), width=w))
            if f.get("tactic"):
                out.append(s.paint("      " + f["tactic"], MUTED))
            if f.get("url"):
                out.append(s.paint("      details: ", MUTED) + s.paint(f["url"], CYAN))
            out.append("")
    footer()
    return "\n".join(out) + "\n"


def to_json(principals, findings, summary, account=None):
    payload = {
        "tool": "pathbreak-audit",
        "version": __version__,
        "account": account,
        "summary": summary,
        "findings": sorted(findings, key=_finding_sort_key),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
