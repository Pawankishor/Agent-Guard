"""Deterministic, versioned authorization policy.

Evaluation order (documented, tested):
  1. Explicit FORBIDs -> DENY (nothing, including a favourable ML score, can override).
  2. Grants for the principal's *server-side* role, first match wins (list order = specificity).
  3. No matching grant -> DENY (default deny).
Outcomes are ALLOW / REQUIRE_APPROVAL / DENY with structured reason codes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Mapping

from ..errors import PolicyUnavailable
from ..common import Outcome, Reason, Resource, Sensitivity

S = Sensitivity


@dataclass(frozen=True)
class Grant:
    tool: str
    resource: str = "*"                      # fnmatch against Resource.identifier
    max_sensitivity: Sensitivity = S.PUBLIC
    outcome: Outcome = Outcome.ALLOW


@dataclass(frozen=True)
class Forbid:
    tool: str
    resource: str = "*"
    roles: tuple[str, ...] | None = None      # None = every role
    reason: Reason = Reason.POLICY_EXPLICIT_FORBID


@dataclass(frozen=True)
class PolicyBundle:
    version: str
    grants: Mapping[str, tuple[Grant, ...]]
    forbids: tuple[Forbid, ...] = ()
    approvers: Mapping[str, tuple[str, ...]] = field(default_factory=dict)   # tool -> roles that may approve


@dataclass(frozen=True)
class PolicyDecision:
    outcome: Outcome
    reasons: tuple[Reason, ...]
    policy_version: str
    matched_rule: str | None = None


def default_bundle() -> PolicyBundle:
    base = (
        Grant("weather.get", "city:*", S.PUBLIC),
        Grant("db.lookup", "courses", S.PUBLIC),
        Grant("file.read", "public/*", S.PUBLIC),
    )
    employee = base + (
        Grant("db.lookup", "employees", S.INTERNAL),
        Grant("file.read", "internal/*", S.INTERNAL),
        Grant("email.send", "internal:*", S.INTERNAL),
        Grant("email.send", "external:*", S.CONFIDENTIAL, Outcome.REQUIRE_APPROVAL),
        Grant("record.update", "employee:*", S.CONFIDENTIAL, Outcome.REQUIRE_APPROVAL),
    )
    manager = employee + (
        Grant("db.lookup", "salaries", S.CONFIDENTIAL),
        Grant("file.read", "confidential/*", S.CONFIDENTIAL, Outcome.REQUIRE_APPROVAL),
    )
    admin = manager + (
        Grant("record.delete", "employee:*", S.CONFIDENTIAL, Outcome.REQUIRE_APPROVAL),
        Grant("command.run", "command:*", S.CRITICAL, Outcome.REQUIRE_APPROVAL),
    )
    return PolicyBundle(
        version="policy-1.0.0",
        grants={"student": base, "employee": employee, "manager": manager, "admin": admin,
                "reviewer": (Grant("weather.get", "city:*", S.PUBLIC),)},
        forbids=(
            Forbid("file.read", "secrets/*"),                                         # nobody reads secrets/
            Forbid("record.delete", roles=("student", "employee", "manager", "reviewer")),
            Forbid("command.run", roles=("student", "employee", "manager", "reviewer")),
        ),
        approvers={
            "record.update": ("manager", "admin"),
            "record.delete": ("admin",),
            "command.run": ("admin",),
            "email.send": ("manager", "admin"),
            "file.read": ("manager", "admin"),
        },
    )


class PolicyEngine:
    """Pure function of (bundle, role, tool, resource). `available=False` simulates an outage."""

    def __init__(self, bundle: PolicyBundle | None = None):
        self.bundle = bundle or default_bundle()
        self.available = True

    @property
    def version(self) -> str:
        return self.bundle.version

    def evaluate(self, role: str, tool: str, resource: Resource) -> PolicyDecision:
        if not self.available:
            raise PolicyUnavailable("policy service unavailable")
        b = self.bundle
        for f in b.forbids:
            if fnmatchcase(tool, f.tool) and fnmatchcase(resource.identifier, f.resource) \
                    and (f.roles is None or role in f.roles):
                return PolicyDecision(Outcome.DENY, (f.reason,), b.version, f"forbid:{f.tool}:{f.resource}")
        grants = b.grants.get(role)
        if not grants:
            return PolicyDecision(Outcome.DENY, (Reason.POLICY_NO_PERMISSION,), b.version, "unknown-role")
        tool_grants = [g for g in grants if g.tool == tool]
        if not tool_grants:
            return PolicyDecision(Outcome.DENY, (Reason.POLICY_NO_PERMISSION,), b.version, None)
        too_sensitive = False
        for g in tool_grants:
            if fnmatchcase(resource.identifier, g.resource):
                if resource.sensitivity <= g.max_sensitivity:
                    reason = (Reason.POLICY_APPROVAL_REQUIRED if g.outcome is Outcome.REQUIRE_APPROVAL
                              else Reason.POLICY_ALLOW_ROLE_PERMISSION)
                    return PolicyDecision(g.outcome, (reason,), b.version, f"grant:{g.tool}:{g.resource}")
                too_sensitive = True
        return PolicyDecision(
            Outcome.DENY,
            (Reason.POLICY_SENSITIVITY_EXCEEDS_GRANT if too_sensitive else Reason.POLICY_RESOURCE_OUT_OF_SCOPE,),
            b.version, None)

    def can_approve(self, reviewer_role: str, tool: str) -> bool:
        if not self.available:
            raise PolicyUnavailable("policy service unavailable")
        return reviewer_role in self.bundle.approvers.get(tool, ())
