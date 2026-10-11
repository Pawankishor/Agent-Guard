"""The Policy Enforcement Point. EVERY tool call goes through ExecutionGateway; it is the only module
that mints execution capabilities.

Pipeline (submit):
  identity -> replay -> rate limit -> tool lookup -> strict schema -> resource classification ->
  detectors -> policy (authoritative) -> trust+ML -> risk (escalate-only) ->
  most_restrictive(policy, risk) -> {DENY | approval request | revalidate + execute} -> output checks -> audit

Fail-closed rules: invalid identity, policy outage, audit outage before a side effect, capability
mismatch => no execution. Unavailable trust/ML/detectors escalate protected operations.
"""
from __future__ import annotations

import json
import re
import time
import uuid
from typing import Any

from ..audit.log import AuditLog
from ..clock import Clock
from ..common import (ContentItem, ExecStatus, Outcome, OutcomeClass, Reason, Resource, Signal, ToolCallRequest,
                      ToolCallResult, args_hash, most_restrictive, sha256_hex)
from ..config import Settings
from ..detection.base import DetectionInput, DetectorSuite
from ..detection.behavior import BehaviorDetector
from ..detection.leakage import contains_canary, mark_untrusted, redact
from ..detection.patterns import PatternDetector
from ..detection.structural import StructuralDetector
from ..errors import (ApprovalError, ArgumentError, AuditUnavailable, AuthError, CapabilityError, ModelUnavailable,
                      PolicyUnavailable, ToolError, ToolTimeout, UnsupportedOperation)
from ..identity.service import IdentityService, Principal
from ..ml.advisory import MlAdvisor, NullAdvisor
from ..policy.engine import PolicyEngine
from ..risk.assess import RiskAssessor
from ..tools.base import ToolEnv, ToolSpec
from ..tools.registry import ToolRegistry
from ..tools.schema import validate
from ..trust.engine import TrustEngine
from .approvals import ApprovalService
from .capability import mint

_RID = re.compile(r"[A-Za-z0-9_-]{8,64}")


class ExecutionGateway:
    def __init__(self, *, settings: Settings, clock: Clock, identity: IdentityService, policy: PolicyEngine,
                 registry: ToolRegistry, env: ToolEnv, approvals: ApprovalService, audit: AuditLog,
                 trust: TrustEngine, suite: DetectorSuite | None = None, risk: RiskAssessor | None = None,
                 ml: MlAdvisor | None = None):
        self.s, self.clock, self.identity, self.policy, self.registry = settings, clock, identity, policy, registry
        self.env, self.approvals, self.audit, self.trust = env, approvals, audit, trust
        self.suite = suite or DetectorSuite([PatternDetector(), StructuralDetector(), _provenance()])
        self.behavior = BehaviorDetector(trust, settings.rate_limit_per_min)
        self.risk = risk or RiskAssessor(settings)
        self.ml: MlAdvisor = ml or NullAdvisor()

    # ------------------------------------------------------------------ helpers
    def _versions(self) -> dict[str, str]:
        v = dict(self.suite.versions); v["policy"] = self.policy.version
        v["behavior"] = self.behavior.version
        return v

    def _log(self, event_type: str, *, must: bool, **kw: Any) -> str | None:
        """Audit write. must=True => failure propagates (caller fails closed); else best-effort."""
        kw.setdefault("detector_versions", self._versions())
        kw.setdefault("model_version", getattr(self.ml, "version", None))
        try:
            return self.audit.record(event_type, **kw)
        except Exception as e:  # noqa: BLE001
            if must:
                raise AuditUnavailable(str(e)) from e
            return None

    def _result(self, rid: str, decision: Outcome, reasons: list[Reason], oc: OutcomeClass, **kw: Any) -> ToolCallResult:
        return ToolCallResult(request_id=rid, decision=decision, reasons=tuple(dict.fromkeys(reasons)),
                              outcome_class=oc, **kw)

    def _scrub(self, sigs: list[Signal]) -> list[dict]:
        d = [s.as_dict() for s in sigs]
        if not self.s.store_excerpts:
            for x in d:
                x["excerpt"] = ""
        return d

    def _claims(self, call: ToolCallRequest) -> dict:
        return {"untrusted_client_claims": {str(k)[:40]: str(v)[:80] for k, v in list(call.client_claims.items())[:10]}}

    def _deny_unauth(self, rid: str, call: ToolCallRequest, e: AuthError) -> ToolCallResult:
        eid = self._log("AUTH_REJECTED", must=False, request_id=rid, tool=call.tool, outcome="DENY",
                        outcome_class=OutcomeClass.POLICY_DENIAL.value, reasons=[e.reason])
        return self._result(rid, Outcome.DENY, [e.reason], OutcomeClass.POLICY_DENIAL,
                            audit_event_ids=(eid,) if eid else ())

    # ------------------------------------------------------------------ main entry
    def submit(self, token: str, call: ToolCallRequest, *, approval_id: str | None = None) -> ToolCallResult:
        rid = call.request_id or str(uuid.uuid4())
        try:
            principal = self.identity.resolve(token)
        except AuthError as e:
            return self._deny_unauth(rid, call, e)
        uid = principal.user_id
        base = dict(principal_id=uid, session_id=principal.session_id, request_id=rid, tool=call.tool)

        def deny(reasons: list[Reason], oc: OutcomeClass, *, event: str = "DECISION", sigs=(), tt=None, spec: ToolSpec | None = None,
                 resource: Resource | None = None, score=None, factors=(), trust_score=None, details=None) -> ToolCallResult:
            eid = self._log(event, must=False, **base, action=spec.action if spec else None,
                            resource_class=resource.sensitivity.name if resource else None, outcome="DENY",
                            outcome_class=oc.value, reasons=reasons, signals=self._scrub(list(sigs)),
                            trust_transition=tt.as_dict() if tt else None, details={**(details or {}), **self._claims(call)})
            return self._result(rid, Outcome.DENY, reasons, oc, risk_score=score, factors=tuple(factors),
                                signals=tuple(self._scrub(list(sigs))), trust_score=trust_score,
                                audit_event_ids=(eid,) if eid else ())

        if not _RID.fullmatch(rid):
            return deny([Reason.ARGS_INVALID], OutcomeClass.POLICY_DENIAL, details={"why": "bad request_id"})
        if not self.trust.claim_request(uid, rid):
            tt = self.trust.record(uid, "REPLAY_ATTEMPT", severity=0.6, request_id=rid)
            return deny([Reason.REPLAY_DETECTED], OutcomeClass.SUSPECTED_MALICIOUS, tt=tt)
        if self.trust.requests_in_window(uid, 60.0) > self.s.rate_limit_per_min:
            tt = self.trust.record(uid, "RATE_ANOMALY", severity=0.7, request_id=rid, dedupe_extra=str(int(self.clock.now() // 60)))
            return deny([Reason.RATE_LIMITED], OutcomeClass.OPERATIONAL_FAILURE, tt=tt)
        spec = self.registry.get(call.tool)
        if spec is None:
            tt = self.trust.record(uid, "MALFORMED_REQUEST", severity=0.5, request_id=rid, detail="unknown_tool")
            return deny([Reason.POLICY_UNKNOWN_TOOL], OutcomeClass.POLICY_DENIAL, tt=tt)
        try:
            args = validate(spec.fields, call.arguments)
            resource = spec.resolver(args, self.env)
        except ArgumentError as e:
            path = e.reason == Reason.PATH_TRAVERSAL
            tt = self.trust.record(uid, "PATH_VIOLATION" if path else "MALFORMED_REQUEST", severity=0.8 if path else 0.5,
                                   request_id=rid, detail=spec.name)
            return deny([e.reason], OutcomeClass.SUSPECTED_MALICIOUS if path else OutcomeClass.POLICY_DENIAL,
                        tt=tt, spec=spec, details={"field": e.field})

        # detectors run before policy so attack attempts are recorded even when policy would deny anyway
        sigs = self.suite.run(DetectionInput(call.user_text or "", tuple(call.untrusted_content), args, spec.name, spec.side_effect))
        sigs += self.behavior.signals_for(uid)
        tt = self._trust_from_signals(uid, rid, sigs)

        try:
            pd = self.policy.evaluate(principal.role, spec.name, resource)
        except PolicyUnavailable:
            return deny([Reason.POLICY_UNAVAILABLE], OutcomeClass.OPERATIONAL_FAILURE, sigs=sigs, tt=tt, spec=spec, resource=resource)
        if pd.outcome is Outcome.DENY:
            t2 = self.trust.record(uid, "POLICY_DENIAL", severity=1.0, request_id=rid, detail=spec.name)
            return deny(list(pd.reasons), OutcomeClass.POLICY_DENIAL, sigs=sigs, tt=t2 if not tt else tt, spec=spec,
                        resource=resource, details={"policy_version": pd.policy_version, "rule": pd.matched_rule})

        snap = self.trust.snapshot(uid, account_created_at=principal.created_at)
        ml_score, ml_ok = self._ml(call)
        ra = self.risk.assess(spec, resource, sigs, snap, ml_score, ml_ok)
        final = most_restrictive(pd.outcome, ra.escalation)
        reasons = list(pd.reasons) + ra.reasons
        common = dict(spec=spec, resource=resource, sigs=sigs, tt=tt, score=ra.score,
                      factors=[f.as_dict() for f in ra.factors], trust_score=snap.score)
        det = {"policy_version": pd.policy_version, "trust_level": snap.level, "trust_quality": snap.data_quality,
               "request_sha256": sha256_hex(call.user_text or ""), "args_hash": args_hash(args), "ml_score": ml_score}

        if final is Outcome.DENY:
            oc = OutcomeClass.SUSPECTED_MALICIOUS if ra.suspected_malicious else OutcomeClass.RISK_ESCALATION
            return deny(reasons, oc, details=det, **common)

        if approval_id is not None:                      # execution of a previously approved call
            return self._run_approved(token, principal, spec, args, resource, rid, approval_id, pd, reasons, ra, sigs, snap)

        if final is Outcome.REQUIRE_APPROVAL:
            aid = self.approvals.create(requester_id=uid, tool=spec.name, action=spec.action, resource=resource.label(),
                                        args_hash=args_hash(args), request_id=rid, policy_version=pd.policy_version,
                                        risk_flags=[r.value for r in reasons])
            try:
                eid = self._log("APPROVAL_REQUESTED", must=True, **base, action=spec.action, resource_class=resource.sensitivity.name,
                                outcome="REQUIRE_APPROVAL", outcome_class=OutcomeClass.OK.value, reasons=reasons,
                                signals=self._scrub(sigs), trust_transition=tt.as_dict() if tt else None,
                                approval_status="PENDING", details={**det, "approval_id": aid, **self._claims(call)})
            except AuditUnavailable:
                return deny([Reason.EXEC_AUDIT_UNAVAILABLE], OutcomeClass.OPERATIONAL_FAILURE, spec=spec, resource=resource)
            return self._result(rid, Outcome.REQUIRE_APPROVAL, reasons + [Reason.APPROVAL_PENDING], OutcomeClass.OK,
                                approval_id=aid, risk_score=ra.score, factors=tuple(f.as_dict() for f in ra.factors),
                                signals=tuple(self._scrub(sigs)), trust_score=snap.score, audit_event_ids=(eid,) if eid else ())

        return self._execute(token, principal, spec, args, resource, rid, reasons, ra, sigs, snap, tt, det, approval_id=None)

    def execute_approved(self, token: str, approval_id: str, call: ToolCallRequest) -> ToolCallResult:
        """Requester re-submits the call; it only runs if it matches the approval EXACTLY."""
        return self.submit(token, call, approval_id=approval_id)

    # ------------------------------------------------------------------ approved path
    def _run_approved(self, token, principal: Principal, spec, args, resource, rid, approval_id, pd, reasons, ra, sigs, snap):
        uid = principal.user_id
        try:
            self.approvals.consume(approval_id=approval_id, requester_id=uid, tool=spec.name, action=spec.action,
                                   resource=resource.label(), args_hash=args_hash(args), policy_version=pd.policy_version)
        except ApprovalError as e:
            tt = None
            if e.reason in (Reason.APPROVAL_BINDING_MISMATCH, Reason.APPROVAL_TAMPERED, Reason.APPROVAL_WRONG_REQUESTER):
                tt = self.trust.record(uid, "APPROVAL_TAMPER_ATTEMPT", severity=0.8, request_id=rid, detail=approval_id[:36])
            eid = self._log("APPROVAL_REJECTED_AT_EXECUTION", must=False, principal_id=uid, session_id=principal.session_id,
                            request_id=rid, tool=spec.name, action=spec.action, outcome="DENY",
                            outcome_class=(OutcomeClass.SUSPECTED_MALICIOUS if tt else OutcomeClass.POLICY_DENIAL).value,
                            reasons=[e.reason], trust_transition=tt.as_dict() if tt else None, details={"approval_id": approval_id})
            return self._result(rid, Outcome.DENY, [e.reason], OutcomeClass.SUSPECTED_MALICIOUS if tt else OutcomeClass.POLICY_DENIAL,
                                audit_event_ids=(eid,) if eid else ())
        return self._execute(token, principal, spec, args, resource, rid, reasons, ra, sigs, snap, None,
                             {"approval_id": approval_id, "args_hash": args_hash(args)}, approval_id=approval_id)

    # ------------------------------------------------------------------ execution
    def _execute(self, token, principal: Principal, spec: ToolSpec, args, resource: Resource, rid, reasons, ra, sigs, snap, tt,
                 det, *, approval_id) -> ToolCallResult:
        uid = principal.user_id
        base = dict(principal_id=uid, session_id=principal.session_id, request_id=rid, tool=spec.name, action=spec.action,
                    resource_class=resource.sensitivity.name)

        def stop(reasons_: list[Reason], oc: OutcomeClass) -> ToolCallResult:
            eid = self._log("EXECUTION_BLOCKED", must=False, **base, outcome="DENY", outcome_class=oc.value, reasons=reasons_, details=det)
            return self._result(rid, Outcome.DENY, reasons_, oc, audit_event_ids=(eid,) if eid else ())

        # Revalidate immediately before execution (identity, role, policy may have changed since the decision).
        try:
            p2 = self.identity.resolve(token)
            if p2.user_id != uid or p2.role != principal.role:
                return stop([Reason.AUTH_ROLE_CHANGED], OutcomeClass.POLICY_DENIAL)
            pd2 = self.policy.evaluate(p2.role, spec.name, resource)
        except AuthError as e:
            return stop([e.reason], OutcomeClass.POLICY_DENIAL)
        except PolicyUnavailable:
            return stop([Reason.POLICY_UNAVAILABLE], OutcomeClass.OPERATIONAL_FAILURE)
        if pd2.outcome is Outcome.DENY or (pd2.outcome is Outcome.REQUIRE_APPROVAL and approval_id is None):
            return stop(list(pd2.reasons), OutcomeClass.POLICY_DENIAL)

        try:   # no audit trail => no side effect
            start = self._log("EXECUTION_STARTED", must=True, **base, outcome="ALLOW", reasons=reasons, approval_status="CONSUMED" if approval_id else None,
                              details={**det, "revalidated_policy": pd2.policy_version})
        except AuditUnavailable:
            return self._result(rid, Outcome.DENY, [Reason.EXEC_AUDIT_UNAVAILABLE], OutcomeClass.OPERATIONAL_FAILURE)

        status, out_text, rs = ExecStatus.SUCCEEDED, None, [Reason.EXEC_OK]
        try:
            raw = spec.invoke(mint(spec.name, args_hash(args), rid), args, self.env)
            text = json.dumps(raw, default=str)
            if len(text.encode()) > self.s.max_output_bytes:
                text = text.encode()[: self.s.max_output_bytes].decode("utf-8", "ignore") + "…[truncated]"
            if contains_canary(text):
                status, rs = ExecStatus.OUTPUT_WITHHELD, [Reason.OUTPUT_CANARY_WITHHELD]
            else:
                text, kinds = redact(text)
                if kinds:
                    rs.append(Reason.OUTPUT_SECRET_REDACTED)
                out_sigs = self.suite.run(DetectionInput("", (ContentItem(f"tool:{spec.name}", text),), {}, spec.name, False))
                sigs = list(sigs) + [Signal(s.name, s.category, s.severity, "tool_output", s.detector, s.version, s.codes, s.excerpt)
                                     for s in out_sigs]
                out_text = mark_untrusted(text, f"tool:{spec.name}")
        except CapabilityError:
            status, rs = ExecStatus.FAILED, [Reason.INTERNAL_ERROR]
        except ToolTimeout:
            status, rs = ExecStatus.TIMEOUT, [Reason.EXEC_TIMEOUT]
        except UnsupportedOperation:
            status, rs = ExecStatus.UNSUPPORTED, [Reason.UNSUPPORTED_OPERATION]
        except ToolError as e:
            status, rs = ExecStatus.FAILED, [Reason.EXEC_FAILED]; det = {**det, "tool_error": e.code}
        except Exception as e:  # noqa: BLE001  (never leak internals to the caller)
            status, rs = ExecStatus.FAILED, [Reason.INTERNAL_ERROR]; det = {**det, "exception": type(e).__name__}

        side = spec.side_effect and status in (ExecStatus.SUCCEEDED, ExecStatus.TIMEOUT)   # timeout: outcome unknown => assume yes
        oc = OutcomeClass.OK if status in (ExecStatus.SUCCEEDED, ExecStatus.OUTPUT_WITHHELD) else OutcomeClass.OPERATIONAL_FAILURE
        eid = self._log("EXECUTION_COMPLETED", must=False, **base, outcome="ALLOW", outcome_class=oc.value, reasons=rs,
                        signals=self._scrub(list(sigs)), exec_status=status.value, details={**det, "side_effect": side})
        return ToolCallResult(request_id=rid, decision=Outcome.ALLOW, reasons=tuple(dict.fromkeys(list(reasons) + rs)), outcome_class=oc,
                              exec_status=status, output=out_text, risk_score=ra.score, factors=tuple(f.as_dict() for f in ra.factors),
                              signals=tuple(self._scrub(list(sigs))), trust_score=snap.score, side_effect_performed=side,
                              audit_event_ids=tuple(x for x in (start, eid) if x))

    # ------------------------------------------------------------------ approvals (reviewer side)
    def decide_approval(self, token: str, approval_id: str, approve: bool, comment: str = "") -> dict:
        try:
            rv = self.identity.resolve(token)
        except AuthError as e:
            return {"ok": False, "reason": e.reason.value}
        try:
            row = self.approvals.get(approval_id)
            can = self.policy.can_approve(rv.role, row["tool"])
            d = self.approvals.decide(approval_id=approval_id, reviewer_id=rv.user_id, reviewer_role=rv.role,
                                      approve=approve, can_approve=can, comment=comment)
        except ApprovalError as e:
            self._log("APPROVAL_DECISION_REFUSED", must=False, principal_id=rv.user_id, session_id=rv.session_id, outcome="DENY",
                      reasons=[e.reason], details={"approval_id": approval_id})
            return {"ok": False, "reason": e.reason.value}
        except PolicyUnavailable:
            return {"ok": False, "reason": Reason.POLICY_UNAVAILABLE.value}
        self._log("APPROVAL_DECIDED", must=False, principal_id=rv.user_id, session_id=rv.session_id, tool=row["tool"],
                  action=row["action"], request_id=row["request_id"], outcome="ALLOW" if approve else "DENY",
                  approval_status=d["status"], details={"approval_id": approval_id, "requester": row["requester_id"]})
        return {"ok": True, "status": d["status"]}

    # ------------------------------------------------------------------ misc
    def _trust_from_signals(self, uid: str, rid: str, sigs: list[Signal]):
        inj = max((s.severity for s in sigs if s.category in ("override_instructions", "role_hijack", "prompt_exfiltration",
                                                              "delimiter_spoof", "policy_tamper", "indirect_injection")
                   and s.severity >= 0.4), default=0.0)
        tt = None
        if inj:
            tt = self.trust.record(uid, "INJECTION_SUSPECTED", severity=inj, request_id=rid)
        if any(s.category == "secret_request" and s.severity >= 0.7 for s in sigs):
            tt = self.trust.record(uid, "SECRET_REQUEST", severity=0.7, request_id=rid) or tt
        return tt

    def _ml(self, call: ToolCallRequest) -> tuple[float | None, bool]:
        try:
            scores = [self.ml.score(call.user_text or "", tool=call.tool, sensitivity=0, source="user")] if call.user_text else [0.0]
            scores += [self.ml.score(i.text, tool=call.tool, sensitivity=0, source="untrusted_content") for i in call.untrusted_content]
            return max(scores), True
        except ModelUnavailable:
            return None, False
        except Exception:  # noqa: BLE001  any inference failure == unavailable, never "50"
            return None, False


def _provenance():
    from ..detection.structural import ProvenanceDetector
    return ProvenanceDetector()
