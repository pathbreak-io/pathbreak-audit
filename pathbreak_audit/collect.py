"""Read-only collection of IAM principals and the actions their policies allow.

Only IAM read calls are made (List*, Get*). Nothing is written, nothing is scanned
beyond IAM. Minimum permissions to run:
  iam:ListUsers, iam:ListRoles, iam:ListGroupsForUser,
  iam:ListAttachedUserPolicies, iam:ListUserPolicies, iam:GetUserPolicy,
  iam:ListAttachedGroupPolicies, iam:ListGroupPolicies, iam:GetGroupPolicy,
  iam:ListAttachedRolePolicies, iam:ListRolePolicies, iam:GetRolePolicy,
  iam:GetPolicy, iam:GetPolicyVersion
(The AWS managed policies SecurityAudit or ViewOnlyAccess both cover these.)
"""
import sys

from .evaluate import _DEFAULT_ROLE_NAME


class CollectionError(Exception):
    pass


# AWS-created / default / reserved roles: service-linked, SSO reserved, Control Tower,
# Organizations, StackSets. Expected to be powerful and not the user's own work, so
# skipped by default (and not even fetched, to keep the scan fast). --include-default-roles
# shows them. Matched on the role Path and on the name regex shared with evaluate.py.
_DEFAULT_ROLE_PATHS = ("/aws-service-role/", "/aws-reserved/")


def _is_default_role(r):
    path = r.get("Path", "") or ""
    if any(path.startswith(p) for p in _DEFAULT_ROLE_PATHS):
        return True
    return bool(_DEFAULT_ROLE_NAME.match(r.get("RoleName", "") or ""))


def _warn(msg):
    sys.stderr.write("pathbreak-audit: " + msg + "\n")


def _as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def _statements_to_grants(document, allow, deny, allow_star):
    """Fold one policy document's statements into the grant sets.

    `allow` is every action allowed on any resource. `allow_star` is the subset allowed
    on Resource "*" (unrestricted), which is what distinguishes "read all secrets"
    (dangerous) from "read one or two scoped secrets" (usually intended).
    """
    if not isinstance(document, dict):
        return
    for st in _as_list(document.get("Statement")):
        if not isinstance(st, dict):
            continue
        effect = st.get("Effect")
        actions = [a for a in _as_list(st.get("Action")) if isinstance(a, str)]
        not_actions = _as_list(st.get("NotAction"))
        resources = [r for r in _as_list(st.get("Resource")) if isinstance(r, str)]
        unrestricted = "*" in resources
        if effect == "Allow":
            if actions:
                allow.update(actions)
                if unrestricted:
                    allow_star.update(actions)
            elif not_actions:
                # Allow on NotAction grants everything except those. We flag broadly
                # rather than miss a dangerous grant; Pathbreak does the precise scoping.
                allow.add("*")
                if unrestricted:
                    allow_star.add("*")
        elif effect == "Deny":
            if actions:
                deny.update(actions)


class Collector:
    def __init__(self, session, include_default_roles=False):
        self.iam = session.client("iam")
        self.include_default_roles = include_default_roles
        self._policy_doc_cache = {}
        self.default_roles_skipped = 0

    # -- managed policy documents (cached by ARN) --
    def _managed_doc(self, arn):
        if arn in self._policy_doc_cache:
            return self._policy_doc_cache[arn]
        doc = None
        try:
            pol = self.iam.get_policy(PolicyArn=arn)["Policy"]
            ver = pol["DefaultVersionId"]
            doc = self.iam.get_policy_version(PolicyArn=arn, VersionId=ver)["PolicyVersion"]["Document"]
        except Exception as e:  # noqa: BLE001
            _warn("could not read managed policy %s (%s)" % (arn, type(e).__name__))
        self._policy_doc_cache[arn] = doc
        return doc

    def _attached(self, list_call, **kw):
        out = []
        try:
            paginator = self.iam.get_paginator(list_call)
            for page in paginator.paginate(**kw):
                out.extend(page.get("AttachedPolicies", []))
        except Exception as e:  # noqa: BLE001
            _warn("could not list attached policies (%s): %s" % (list_call, type(e).__name__))
        return out

    def _inline_names(self, list_call, **kw):
        out = []
        try:
            paginator = self.iam.get_paginator(list_call)
            for page in paginator.paginate(**kw):
                out.extend(page.get("PolicyNames", []))
        except Exception as e:  # noqa: BLE001
            _warn("could not list inline policies (%s): %s" % (list_call, type(e).__name__))
        return out

    def _grants_for(self, attached, inline_docs):
        allow, deny, allow_star = set(), set(), set()
        for ap in attached:
            doc = self._managed_doc(ap.get("PolicyArn"))
            if doc:
                _statements_to_grants(doc, allow, deny, allow_star)
        for doc in inline_docs:
            _statements_to_grants(doc, allow, deny, allow_star)
        return allow, deny, allow_star

    def _role_grants(self, role_name):
        attached = self._attached("list_attached_role_policies", RoleName=role_name)
        inline = []
        for name in self._inline_names("list_role_policies", RoleName=role_name):
            try:
                inline.append(self.iam.get_role_policy(RoleName=role_name, PolicyName=name)["PolicyDocument"])
            except Exception as e:  # noqa: BLE001
                _warn("could not read inline role policy %s/%s (%s)" % (role_name, name, type(e).__name__))
        return self._grants_for(attached, inline)

    def _group_grants(self, group_name):
        attached = self._attached("list_attached_group_policies", GroupName=group_name)
        inline = []
        for name in self._inline_names("list_group_policies", GroupName=group_name):
            try:
                inline.append(self.iam.get_group_policy(GroupName=group_name, PolicyName=name)["PolicyDocument"])
            except Exception as e:  # noqa: BLE001
                _warn("could not read inline group policy %s/%s (%s)" % (group_name, name, type(e).__name__))
        return self._grants_for(attached, inline)

    def _user_grants(self, user_name):
        attached = self._attached("list_attached_user_policies", UserName=user_name)
        inline = []
        for name in self._inline_names("list_user_policies", UserName=user_name):
            try:
                inline.append(self.iam.get_user_policy(UserName=user_name, PolicyName=name)["PolicyDocument"])
            except Exception as e:  # noqa: BLE001
                _warn("could not read inline user policy %s/%s (%s)" % (user_name, name, type(e).__name__))
        allow, deny, allow_star = self._grants_for(attached, inline)
        # user inherits its groups' permissions
        try:
            paginator = self.iam.get_paginator("list_groups_for_user")
            for page in paginator.paginate(UserName=user_name):
                for g in page.get("Groups", []):
                    ga, gd, gs = self._group_grants(g["GroupName"])
                    allow |= ga
                    deny |= gd
                    allow_star |= gs
        except Exception as e:  # noqa: BLE001
            _warn("could not list groups for user %s (%s)" % (user_name, type(e).__name__))
        return allow, deny, allow_star

    def principals(self):
        out = []
        tty = sys.stderr.isatty()

        def tick(label, i, n):
            if tty:
                sys.stderr.write("\rpathbreak-audit: reading %s %d/%d " % (label, i, n))
                sys.stderr.flush()

        # roles: list first (fast), then fetch each one's policies (the slow part)
        try:
            roles = []
            for page in self.iam.get_paginator("list_roles").paginate():
                for r in page.get("Roles", []):
                    if not self.include_default_roles and _is_default_role(r):
                        self.default_roles_skipped += 1
                        continue
                    roles.append(r)
        except Exception as e:  # noqa: BLE001
            raise CollectionError("could not list roles: %s. Check your credentials and IAM read access." % type(e).__name__)
        for i, r in enumerate(roles, 1):
            tick("roles", i, len(roles))
            allow, deny, allow_star = self._role_grants(r["RoleName"])
            out.append({"name": r["RoleName"], "arn": r.get("Arn"), "type": "role",
                        "allow": sorted(allow), "deny": sorted(deny), "allow_star": sorted(allow_star)})
        if roles and tty:
            sys.stderr.write("\n")

        # users
        try:
            users = []
            for page in self.iam.get_paginator("list_users").paginate():
                users.extend(page.get("Users", []))
        except Exception as e:  # noqa: BLE001
            _warn("could not list users (%s); reporting roles only" % type(e).__name__)
            users = []
        for i, u in enumerate(users, 1):
            tick("users", i, len(users))
            allow, deny, allow_star = self._user_grants(u["UserName"])
            out.append({"name": u["UserName"], "arn": u.get("Arn"), "type": "user",
                        "allow": sorted(allow), "deny": sorted(deny), "allow_star": sorted(allow_star)})
        if users and tty:
            sys.stderr.write("\n")
        return out


def collect(profile=None, region=None, include_default_roles=False):
    try:
        import boto3
    except ImportError:
        raise CollectionError("boto3 is required for a live scan. Install it with: pip install boto3")
    session = boto3.Session(profile_name=profile, region_name=region)
    account = None
    try:
        account = session.client("sts").get_caller_identity().get("Account")
    except Exception:  # noqa: BLE001
        pass
    _warn("scanning account %s (read-only IAM). On a large account this can take a minute."
          % (account or "default profile"))
    collector = Collector(session, include_default_roles=include_default_roles)
    principals = collector.principals()
    return account, principals, collector.default_roles_skipped
