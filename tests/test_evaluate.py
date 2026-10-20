"""Unit tests for the matching logic. Run with: python -m pytest  (or python -m unittest)."""
import unittest

from pathbreak_audit.evaluate import evaluate, summarize, is_admin, is_default_role
from pathbreak_audit.catalogue import load_checks


CHECK_DIRECT = {
    "id": "x-direct", "title": "Direct thing", "needs_actions": ["iam:CreateAccessKey"],
    "service": "IAM", "grants": "g", "why": "w", "fix": "f", "tactic": "persistence",
    "mitre": {"id": "T0000", "name": "n"}, "tier": 3, "combination": False, "url": "u",
}
CHECK_COMBO = {
    "id": "x-combo", "title": "Combo thing", "needs_actions": ["iam:PassRole", "ec2:RunInstances"],
    "service": "EC2", "grants": "g", "why": "w", "fix": "f", "tactic": "privilege-escalation",
    "mitre": None, "tier": 3, "combination": True, "url": "u",
}
CHECKS = [CHECK_DIRECT, CHECK_COMBO]


class TestEvaluate(unittest.TestCase):
    def test_exact_direct_match(self):
        p = [{"name": "r", "type": "role", "arn": "a", "allow": ["iam:CreateAccessKey"], "deny": []}]
        f = evaluate(p, CHECKS)
        self.assertEqual([x["check_id"] for x in f], ["x-direct"])

    def test_wildcard_grant_matches(self):
        p = [{"name": "r", "type": "role", "arn": "a", "allow": ["iam:*"], "deny": []}]
        f = evaluate(p, CHECKS)
        self.assertIn("x-direct", [x["check_id"] for x in f])

    def test_star_grants_everything(self):
        p = [{"name": "r", "type": "role", "arn": "a", "allow": ["*"], "deny": []}]
        ids = {x["check_id"] for x in evaluate(p, CHECKS)}
        self.assertEqual(ids, {"x-direct", "x-combo"})

    def test_combination_needs_all(self):
        only_one = [{"name": "r", "type": "role", "arn": "a", "allow": ["iam:PassRole"], "deny": []}]
        self.assertEqual(evaluate(only_one, CHECKS), [])
        both = [{"name": "r", "type": "role", "arn": "a",
                 "allow": ["iam:PassRole", "ec2:RunInstances"], "deny": []}]
        self.assertEqual([x["check_id"] for x in evaluate(both, CHECKS)], ["x-combo"])

    def test_explicit_deny_blocks(self):
        p = [{"name": "r", "type": "role", "arn": "a",
              "allow": ["iam:*"], "deny": ["iam:CreateAccessKey"]}]
        self.assertEqual(evaluate(p, CHECKS), [])

    def test_case_insensitive(self):
        p = [{"name": "r", "type": "role", "arn": "a", "allow": ["IAM:createaccesskey"], "deny": []}]
        self.assertEqual([x["check_id"] for x in evaluate(p, CHECKS)], ["x-direct"])

    def test_summary(self):
        p = [{"name": "r", "type": "role", "arn": "a", "allow": ["*"], "deny": []}]
        s = summarize(p, evaluate(p, CHECKS))
        self.assertEqual(s["findings_total"], 2)
        self.assertEqual(s["principals_with_findings"], 1)


class TestCatalogue(unittest.TestCase):
    def test_bundled_catalogue_loads(self):
        meta, checks = load_checks()
        self.assertGreater(len(checks), 100)
        for c in checks:
            self.assertTrue(c["needs_actions"])
            self.assertTrue(c["url"].startswith("https://pathbreak.io/aws-privilege-escalation-map/"))


class TestClassification(unittest.TestCase):
    def test_is_admin(self):
        self.assertTrue(is_admin({"allow": ["*"]}))
        self.assertFalse(is_admin({"allow": ["iam:*", "s3:*"]}))
        self.assertFalse(is_admin({"allow": []}))

    def test_is_default_role(self):
        for name in ("AWSControlTowerExecution", "AWSReservedSSO_Admin_a1b2",
                     "OrganizationAccountAccessRole", "AWSServiceRoleForSupport"):
            self.assertTrue(is_default_role({"type": "role", "name": name}), name)
        self.assertFalse(is_default_role({"type": "role", "name": "octo-deploy"}))
        self.assertFalse(is_default_role({"type": "user", "name": "AWSControlTowerExecution"}))


SECRET_CHECK = {
    "id": "secrets-getsecretvalue", "title": "Read secret", "needs_actions": ["secretsmanager:GetSecretValue"],
    "service": "Secrets Manager", "grants": "g", "why": "w", "fix": "f", "tactic": "credential-access",
    "mitre": None, "tier": 1, "combination": False, "url": "u",
}


class TestScopedReads(unittest.TestCase):
    def test_scoped_secret_not_flagged_by_default(self):
        scoped = [{"name": "dev", "type": "user", "arn": "a",
                   "allow": ["secretsmanager:GetSecretValue"], "allow_star": [], "deny": []}]
        self.assertEqual(evaluate(scoped, [SECRET_CHECK], star_tactics={"credential-access"}), [])

    def test_read_all_secrets_flagged(self):
        readall = [{"name": "ops", "type": "user", "arn": "a",
                    "allow": ["secretsmanager:*"], "allow_star": ["secretsmanager:*"], "deny": []}]
        got = evaluate(readall, [SECRET_CHECK], star_tactics={"credential-access"})
        self.assertEqual([f["check_id"] for f in got], ["secrets-getsecretvalue"])

    def test_scoped_flagged_when_tactic_not_star_gated(self):
        # When a tactic is not in star_tactics (as --include-access leaves non-context
        # tactics), a scoped grant is matched normally.
        scoped = [{"name": "dev", "type": "user", "arn": "a",
                   "allow": ["secretsmanager:GetSecretValue"], "allow_star": [], "deny": []}]
        got = evaluate(scoped, [SECRET_CHECK])  # no star_tactics = scoped flagged too
        self.assertEqual([f["check_id"] for f in got], ["secrets-getsecretvalue"])


if __name__ == "__main__":
    unittest.main()
