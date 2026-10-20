"""Load the bundled check catalogue (checks.json)."""
import json
import os

_DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "checks.json")


def load_checks(path=None):
    """Return (meta, checks). checks is a list of dicts, worst-first."""
    with open(path or _DATA, encoding="utf-8") as f:
        data = json.load(f)
    checks = data.get("checks") or []
    meta = {k: v for k, v in data.items() if k != "checks"}
    return meta, checks
