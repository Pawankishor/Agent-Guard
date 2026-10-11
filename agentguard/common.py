"""Shared value types. Everything security-relevant is an enum or frozen dataclass."""
from __future__ import annotations

import enum
import hashlib
import json
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Mapping


class Outcome(str, enum.Enum):
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"

    @property
    def rank(self) -> int:
        return {"ALLOW": 0, "REQUIRE_APPROVAL": 1, "DENY": 2}[self.value]


def most_restrictive(*outcomes: Outcome) -> Outcome:
    return max(outcomes, key=lambda o: o.rank)


class Sensitivity(enum.IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    CRITICAL = 3


class RiskClass(enum.IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class OutcomeClass(str, enum.Enum):
    """Why something did not proceed. A policy denial is NOT evidence of malice."""
    OK = "OK"
    POLICY_DENIAL = "POLICY_DENIAL"
    RISK_ESCALATION = "RISK_ESCALATION"
    OPERATIONAL_FAILURE = "OPERATIONAL_FAILURE"
    SUSPECTED_MALICIOUS = "SUSPECTED_MALICIOUS"      # automated, unverified
    CONFIRMED_MALICIOUS = "CONFIRMED_MALICIOUS"      # only ever set by human review


class ExecStatus(str, enum.Enum):
    NOT_EXECUTED = "NOT_EXECUTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    UNSUPPORTED = "UNSUPPORTED"
    OUTPUT_WITHHELD = "OUTPUT_WITHHELD"


class Reason(str, enum.Enum):
    # authentication / identity
    AUTH_BAD_CREDENTIALS = "AUTH_BAD_CREDENTIALS"
    AUTH_INVALID_SESSION = "AUTH_INVALID_SESSION"
    AUTH_SESSION_EXPIRED = "AUTH_SESSION_EXPIRED"
    AUTH_ACCOUNT_DISABLED = "AUTH_ACCOUNT_DISABLED"
    AUTH_LOCKED_OUT = "AUTH_LOCKED_OUT"
    AUTH_ROLE_CHANGED = "AUTH_ROLE_CHANGED"
    # policy
    POLICY_ALLOW_ROLE_PERMISSION = "POLICY_ALLOW_ROLE_PERMISSION"
    POLICY_APPROVAL_REQUIRED = "POLICY_APPROVAL_REQUIRED"
    POLICY_NO_PERMISSION = "POLICY_NO_PERMISSION"
    POLICY_RESOURCE_OUT_OF_SCOPE = "POLICY_RESOURCE_OUT_OF_SCOPE"
    POLICY_SENSITIVITY_EXCEEDS_GRANT = "POLICY_SENSITIVITY_EXCEEDS_GRANT"
    POLICY_EXPLICIT_FORBID = "POLICY_EXPLICIT_FORBID"
    POLICY_UNKNOWN_TOOL = "POLICY_UNKNOWN_TOOL"
    POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"
    POLICY_VERSION_CHANGED = "POLICY_VERSION_CHANGED"
    # request validity
    ARGS_INVALID = "ARGS_INVALID"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    RATE_LIMITED = "RATE_LIMITED"
    UNSUPPORTED_OPERATION = "UNSUPPORTED_OPERATION"
    # risk layer
    RISK_DIRECT_INJECTION = "RISK_DIRECT_INJECTION"
    RISK_INJECTION_MEDIUM = "RISK_INJECTION_MEDIUM"
    RISK_CONTENT_DERIVED_ACTION = "RISK_CONTENT_DERIVED_ACTION"
    RISK_SCORE_HIGH = "RISK_SCORE_HIGH"
    RISK_SECRET_DISCLOSURE_REQUEST = "RISK_SECRET_DISCLOSURE_REQUEST"
    RISK_TRUST_LOW = "RISK_TRUST_LOW"
    RISK_TRUST_UNAVAILABLE = "RISK_TRUST_UNAVAILABLE"
    RISK_TRUST_RESTRICTED = "RISK_TRUST_RESTRICTED"
    RISK_ML_UNAVAILABLE = "RISK_ML_UNAVAILABLE"
    RISK_DETECTOR_ERROR = "RISK_DETECTOR_ERROR"
    # approvals
    APPROVAL_PENDING = "APPROVAL_PENDING"
    APPROVAL_NOT_FOUND = "APPROVAL_NOT_FOUND"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    APPROVAL_NOT_APPROVED = "APPROVAL_NOT_APPROVED"
    APPROVAL_ALREADY_USED = "APPROVAL_ALREADY_USED"
    APPROVAL_BINDING_MISMATCH = "APPROVAL_BINDING_MISMATCH"
    APPROVAL_TAMPERED = "APPROVAL_TAMPERED"
    APPROVAL_SELF_APPROVAL = "APPROVAL_SELF_APPROVAL"
    APPROVAL_UNAUTHORIZED_REVIEWER = "APPROVAL_UNAUTHORIZED_REVIEWER"
    APPROVAL_WRONG_REQUESTER = "APPROVAL_WRONG_REQUESTER"
    # execution
    EXEC_OK = "EXEC_OK"
    EXEC_FAILED = "EXEC_FAILED"
    EXEC_TIMEOUT = "EXEC_TIMEOUT"
    EXEC_AUDIT_UNAVAILABLE = "EXEC_AUDIT_UNAVAILABLE"
    OUTPUT_SECRET_REDACTED = "OUTPUT_SECRET_REDACTED"
    OUTPUT_CANARY_WITHHELD = "OUTPUT_CANARY_WITHHELD"
    INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass(frozen=True)
class Resource:
    kind: str
    identifier: str
    sensitivity: Sensitivity

    def label(self) -> str:
        return f"{self.kind}:{self.identifier}"


@dataclass(frozen=True)
class ContentItem:
    """Anything the agent read that did not come from the authenticated user
    (retrieved document, web page, tool output). Untrusted by construction."""
    source: str
    text: str


@dataclass(frozen=True)
class ToolCallRequest:
    tool: str
    arguments: Mapping[str, Any]
    user_text: str = ""                                   # what the human actually typed
    untrusted_content: tuple[ContentItem, ...] = ()      # what the agent read before proposing this call
    request_id: str | None = None
    client_claims: Mapping[str, Any] = field(default_factory=dict)  # purpose/urgency/role: logged, NEVER trusted


@dataclass(frozen=True)
class Signal:
    """A detector observation. Signals can raise scrutiny; they can never grant anything."""
    name: str
    category: str
    severity: float                   # 0..1
    source: str                       # user | untrusted_content | tool_output | arguments | system
    detector: str
    version: str
    codes: tuple[str, ...] = ()
    excerpt: str = ""
    error: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "category": self.category, "severity": round(self.severity, 3),
                "source": self.source, "detector": f"{self.detector}@{self.version}",
                "codes": list(self.codes), "excerpt": self.excerpt, "error": self.error}


@dataclass
class ToolCallResult:
    request_id: str
    decision: Outcome
    reasons: tuple[Reason, ...]
    outcome_class: OutcomeClass
    exec_status: ExecStatus = ExecStatus.NOT_EXECUTED
    output: Any = None                       # untrusted-marked string when present
    approval_id: str | None = None
    risk_score: float | None = None
    factors: tuple[dict[str, Any], ...] = ()
    signals: tuple[dict[str, Any], ...] = ()
    trust_score: float | None = None
    side_effect_performed: bool = False
    audit_event_ids: tuple[str, ...] = ()

    @property
    def executed(self) -> bool:
        return self.exec_status == ExecStatus.SUCCEEDED


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def args_hash(args: Mapping[str, Any]) -> str:
    """Canonical hash of *validated* arguments (the thing approvals bind to)."""
    return sha256_hex(canonical_json(dict(args)))


def nfc(s: str) -> str:
    return unicodedata.normalize("NFC", s)
