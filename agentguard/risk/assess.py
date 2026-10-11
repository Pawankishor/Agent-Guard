"""Risk aggregation.

Hard guarantees (tested):
  * The assessor returns an *escalation* (ALLOW | REQUIRE_APPROVAL | DENY). The gateway combines it
    with the policy outcome via most_restrictive(), so risk can only tighten, never relax.
  * ML contributes only an advisory score (max +15 points) and can never cause a DENY nor lower risk.
  * Missing/failed components (trust, ML, detectors) escalate protected operations; they never allow.
Weights below are documented design choices, NOT calibrated probabilities. See docs/LIMITATIONS.md.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..common import Outcome, Reason, Resource, RiskClass, Signal
from ..config import Settings
from ..tools.base import ToolSpec
from ..trust.engine import TrustSnapshot

_BASE = {RiskClass.LOW: 5.0, RiskClass.MEDIUM: 25.0, RiskClass.HIGH: 45.0, RiskClass.CRITICAL: 60.0}


@dataclass(frozen=True)
class Factor:
    name: str
    points: float
    detail: str = ""

    def as_dict(self) -> dict:
        return {"name": self.name, "points": round(self.points, 2), "detail": self.detail}


@dataclass
class RiskAssessment:
    score: float
    level: str
    escalation: Outcome
    reasons: list[Reason] = field(default_factory=list)
    factors: list[Factor] = field(default_factory=list)
    suspected_malicious: bool = False


def _level(score: float) -> str:
    return "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH" if score < 75 else "CRITICAL"


class RiskAssessor:
    def __init__(self, settings: Settings):
        self.s = settings

    def assess(self, spec: ToolSpec, resource: Resource, signals: list[Signal], trust: TrustSnapshot,
               ml_score: float | None, ml_available: bool) -> RiskAssessment:
        f: list[Factor] = []
        reasons: list[Reason] = []
        protected = spec.side_effect or spec.risk_class >= RiskClass.MEDIUM

        f.append(Factor("tool_risk_class", _BASE[spec.risk_class], spec.risk_class.name))
        if spec.side_effect and not spec.reversible:
            f.append(Factor("irreversible_side_effect", 10.0))
        if resource.sensitivity:
            f.append(Factor("resource_sensitivity", 5.0 * int(resource.sensitivity), resource.sensitivity.name))

        def top(src: str | None = None, cat: str | None = None) -> float:
            vals = [s.severity for s in signals if not s.error and (src is None or s.source == src)
                    and (cat is None or s.category == cat)]
            return max(vals, default=0.0)

        user_inj = max((s.severity for s in signals if s.source == "user" and s.category in
                        ("override_instructions", "role_hijack", "prompt_exfiltration", "delimiter_spoof", "policy_tamper")),
                       default=0.0)
        content_inj = max((s.severity for s in signals if s.source == "untrusted_content" and not s.error), default=0.0)
        derived = max([s.severity for s in signals if s.name == "provenance:content_derived_argument"], default=0.0)
        secret_req = max((s.severity for s in signals if s.category == "secret_request"), default=0.0)
        struct = max((s.severity for s in signals if s.source in ("user", "untrusted_content")
                      and s.category in ("hidden_text", "obfuscation")), default=0.0)
        behavior = max((s.severity for s in signals if s.category in ("rate", "probing")), default=0.0)
        det_err = any(s.error for s in signals)

        if user_inj:
            f.append(Factor("user_text_injection", 40.0 * user_inj))
        if content_inj:
            f.append(Factor("untrusted_content_injection", 30.0 * content_inj))
        if derived:
            f.append(Factor("content_derived_argument", 25.0 * min(1.0, derived / 0.6)))
        if struct:
            f.append(Factor("structural_obfuscation", 10.0 * struct))
        if behavior:
            f.append(Factor("behavioural_anomaly", 15.0 * behavior))
        if trust.usable:
            if trust.score < 1.0:
                f.append(Factor("trust_penalty", 30.0 * (1.0 - trust.score), trust.level))
        else:
            f.append(Factor("trust_unavailable", 15.0, trust.data_quality))
        if trust.new_account and spec.side_effect:
            f.append(Factor("new_account", 5.0))
        if ml_available and ml_score is not None:
            f.append(Factor("ml_advisory", 15.0 * max(0.0, min(1.0, ml_score)), f"p={ml_score:.2f}"))

        score = max(0.0, min(100.0, sum(x.points for x in f)))
        esc = Outcome.ALLOW
        malicious = False

        def escalate(to: Outcome, why: Reason) -> None:
            nonlocal esc
            if to.rank > esc.rank:
                esc = to
            if why not in reasons:
                reasons.append(why)

        # --- deterministic rules, strongest first ---
        if user_inj >= self.s.deny_injection_threshold:
            escalate(Outcome.DENY, Reason.RISK_DIRECT_INJECTION); malicious = True
        if spec.side_effect and derived >= 0.5 and content_inj >= 0.5:
            escalate(Outcome.DENY, Reason.RISK_CONTENT_DERIVED_ACTION); malicious = True
        if trust.level == "RESTRICTED" and protected:
            escalate(Outcome.DENY, Reason.RISK_TRUST_RESTRICTED)
        if secret_req >= 0.7 and spec.name != "weather.get":
            escalate(Outcome.REQUIRE_APPROVAL, Reason.RISK_SECRET_DISCLOSURE_REQUEST); malicious = malicious or secret_req >= 0.85
        if spec.side_effect and (0.4 <= user_inj < self.s.deny_injection_threshold or 0.4 <= content_inj):
            escalate(Outcome.REQUIRE_APPROVAL, Reason.RISK_INJECTION_MEDIUM)
        if protected and score >= self.s.approval_score_threshold:
            escalate(Outcome.REQUIRE_APPROVAL, Reason.RISK_SCORE_HIGH)
        if protected and trust.usable and trust.level in ("LOW", "WATCH") and spec.side_effect:
            escalate(Outcome.REQUIRE_APPROVAL, Reason.RISK_TRUST_LOW)
        if protected and not trust.usable:
            escalate(Outcome.REQUIRE_APPROVAL, Reason.RISK_TRUST_UNAVAILABLE)
        if protected and not ml_available and self.s.ml_required_for_protected:
            escalate(Outcome.REQUIRE_APPROVAL, Reason.RISK_ML_UNAVAILABLE)
        if protected and det_err:
            escalate(Outcome.REQUIRE_APPROVAL, Reason.RISK_DETECTOR_ERROR)

        return RiskAssessment(score, _level(score), esc, reasons, f, malicious)
