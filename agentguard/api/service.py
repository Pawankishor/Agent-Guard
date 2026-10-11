"""High-level facade. Usable from any Python app (no Streamlit dependency)."""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from ..audit.log import AuditLog
from ..clock import Clock
from ..common import ToolCallRequest, ToolCallResult, sha256_hex
from ..config import Settings
from ..db import Database
from ..detection.base import DetectorSuite
from ..detection.patterns import PatternDetector
from ..detection.structural import ProvenanceDetector, StructuralDetector
from ..errors import AuthError
from ..execution.approvals import ApprovalService
from ..execution.gateway import ExecutionGateway
from ..identity.service import IdentityService
from ..ml.advisory import MlAdvisor, NullAdvisor
from ..ml.registry import ModelRegistry, RegistryAdvisor
from ..policy.engine import PolicyBundle, PolicyEngine
from ..tools.base import ToolEnv
from ..tools.registry import ToolRegistry, default_registry
from ..tools.sandbox import seed_sandbox
from ..tools.weather import SimulatedWeather
from ..trust.engine import TrustEngine


class AgentGuard:
    def __init__(self, settings: Settings, *, clock: Clock | None = None, ml: MlAdvisor | None = None,
                 policy_bundle: PolicyBundle | None = None, registry: ToolRegistry | None = None, weather: Any = None):
        self.settings = settings.validate()
        self.clock = clock or Clock()
        self.db = Database(settings.security_db)
        self.db.migrate()
        sandbox_db = seed_sandbox(settings.sandbox_dir)
        self.identity = IdentityService(self.db, self.clock, settings)
        self.trust = TrustEngine(self.db, self.clock, skew_s=settings.clock_skew_s)
        self.audit = AuditLog(self.db, self.clock, settings.hmac_key)
        self.policy = PolicyEngine(policy_bundle)
        self.registry = registry or default_registry()
        self.env = ToolEnv(settings.sandbox_dir, sandbox_db, weather or SimulatedWeather(), settings.internal_email_domains,
                           self.clock, settings.max_output_bytes)
        self.approvals = ApprovalService(self.db, self.clock, settings)
        self.models = ModelRegistry(self.db, self.clock, settings.model_dir)
        if ml is None:
            ml = RegistryAdvisor(self.models)       # default: whatever model a human approved+activated (or 'unavailable')
        self.gateway = ExecutionGateway(settings=settings, clock=self.clock, identity=self.identity, policy=self.policy,
                                        registry=self.registry, env=self.env, approvals=self.approvals, audit=self.audit,
                                        trust=self.trust, ml=ml,
                                        suite=DetectorSuite([PatternDetector(), StructuralDetector(), ProvenanceDetector()]))

    # --- identity -------------------------------------------------------------------------
    def provision_user(self, username: str, password: str, role: str, display_name: str | None = None) -> str:
        """Server-side provisioning only. There is deliberately no self-signup path."""
        uid = self.identity.create_user(username, password, role, display_name)
        self.audit.record("USER_PROVISIONED", principal_id=uid, details={"role": role})
        return uid

    def login(self, username: str, password: str) -> str:
        try:
            token, uid = self.identity.authenticate(username, password)
        except AuthError as e:
            uid = getattr(e, "user_id", None)
            tt = self.trust.record(uid, "AUTH_FAILURE", severity=1.0, request_id=None,
                                   dedupe_extra=str(self.clock.now())) if uid else None
            self.audit.record("AUTH_FAILED", principal_id=uid, outcome="DENY", reasons=[e.reason],
                              trust_transition=tt.as_dict() if tt else None, details={"username_sha256": sha256_hex(username or "")})
            raise
        self.audit.record("AUTH_OK", principal_id=uid)
        return token

    def logout(self, token: str) -> None:
        self.identity.revoke(token)

    # --- tool calls -----------------------------------------------------------------------
    def submit_tool_call(self, token: str, call: ToolCallRequest) -> ToolCallResult:
        return self.gateway.submit(token, call)

    def decide_approval(self, reviewer_token: str, approval_id: str, approve: bool, comment: str = "") -> dict:
        return self.gateway.decide_approval(reviewer_token, approval_id, approve, comment)

    def execute_approved(self, token: str, approval_id: str, call: ToolCallRequest) -> ToolCallResult:
        return self.gateway.execute_approved(token, approval_id, call)

    # --- trust / review (reviewer-gated) ------------------------------------------------------
    def _require_reviewer(self, token: str):
        p = self.identity.resolve(token)
        if p.role not in ("reviewer", "admin"):
            raise AuthError(__import__("agentguard.common", fromlist=["Reason"]).Reason.POLICY_NO_PERMISSION)
        return p

    def review_trust_event(self, reviewer_token: str, event_id: str, verdict: str, evidence: str) -> dict:
        """verdict: 'false_positive' (negate the event) | 'confirmed_malicious' (verified penalty)."""
        rv = self._require_reviewer(reviewer_token)
        with self.db.read() as c:
            ev = c.execute("SELECT user_id,request_id FROM trust_events WHERE event_id=?", (event_id,)).fetchone()
        if ev is None:
            return {"ok": False, "reason": "EVENT_NOT_FOUND"}
        if verdict == "false_positive":
            tt = self.trust.record(ev["user_id"], "FALSE_POSITIVE_CLEARED", negates=event_id, verified=True, detail=evidence[:100])
        elif verdict == "confirmed_malicious":
            tt = self.trust.record(ev["user_id"], "CONFIRMED_MALICIOUS", severity=1.0, verified=True, request_id=ev["request_id"],
                                   dedupe_extra=event_id, detail=evidence[:100])
        else:
            return {"ok": False, "reason": "BAD_VERDICT"}
        self.audit.record("TRUST_REVIEWED", principal_id=rv.user_id, outcome=verdict.upper(), trust_transition=tt.as_dict(),
                          details={"subject_user": ev["user_id"], "event_id": event_id, "evidence": evidence})
        return {"ok": True, "transition": tt.as_dict()}

    def submit_label(self, reviewer_token: str, *, text: str, label: int, evidence: str, source: str = "human_review",
                     subject_event_id: str | None = None, supersedes: str | None = None) -> str:
        """Verified labels only. Model predictions can NEVER become labels."""
        rv = self._require_reviewer(reviewer_token)
        if source not in ("human_review", "curated"):
            raise ValueError("labels must come from human review or curated sources, never from model output")
        if not evidence.strip():
            raise ValueError("evidence is required")
        lid = str(uuid.uuid4())
        from ..detection.leakage import redact
        ex, _ = redact(text)
        with self.db.tx() as c:
            c.execute("INSERT INTO labels(label_id,subject_event_id,text_sha256,text_excerpt,label,source,reviewer_id,evidence,created_at,supersedes)"
                      " VALUES(?,?,?,?,?,?,?,?,?,?)", (lid, subject_event_id, sha256_hex(text), ex[:300], int(label), source,
                                                        rv.user_id, evidence[:500], self.clock.now(), supersedes))
        self.audit.record("LABEL_SUBMITTED", principal_id=rv.user_id, details={"label_id": lid, "label": int(label), "source": source})
        return lid

    def trust_snapshot_for(self, user_id: str):
        u = self.identity.get_user(user_id)
        return self.trust.snapshot(user_id, account_created_at=u["created_at"] if u else None)

    # --- model lifecycle (human-gated; never runs per request) ------------------------------------
    def model_register(self, reviewer_token: str, artifact: Path) -> str:
        rv = self._require_reviewer(reviewer_token)
        v = self.models.register_candidate(artifact)
        self.audit.record("MODEL_REGISTERED", principal_id=rv.user_id, details={"version": v})
        return v

    def model_gate(self, reviewer_token: str, version: str) -> tuple[bool, dict]:
        rv = self._require_reviewer(reviewer_token)
        ok, rep = self.models.evaluate_gate(version)
        self.audit.record("MODEL_GATE", principal_id=rv.user_id, outcome="PASS" if ok else "FAIL", details={"version": version, "reasons": rep["reasons"]})
        return ok, rep

    def model_approve_and_activate(self, reviewer_token: str, version: str) -> None:
        rv = self._require_reviewer(reviewer_token)
        self.models.approve(version, rv.user_id)
        self.models.activate(version)
        self.audit.record("MODEL_ACTIVATED", principal_id=rv.user_id, model_version=version)

    def model_rollback(self, reviewer_token: str) -> str:
        rv = self._require_reviewer(reviewer_token)
        v = self.models.rollback()
        self.audit.record("MODEL_ROLLED_BACK", principal_id=rv.user_id, model_version=v)
        return v

    # --- authorised read APIs (the dashboard is only a client of these; it enforces nothing itself) ---
    def _role(self, token: str, roles: tuple[str, ...]):
        from ..common import Reason
        p = self.identity.resolve(token)
        if p.role not in roles:
            raise AuthError(Reason.POLICY_NO_PERMISSION)
        return p

    def whoami(self, token: str):
        return self.identity.resolve(token)

    def audit_search(self, token: str, **filters):
        self._role(token, ("reviewer", "admin"))
        return self.audit.search(**filters)

    def audit_verify(self, token: str):
        self._role(token, ("reviewer", "admin"))
        return self.audit.verify_chain()

    def pending_approvals(self, token: str):
        self._role(token, ("manager", "admin"))
        return self.approvals.pending()

    def list_users(self, token: str):
        self._role(token, ("reviewer", "admin"))
        with self.db.read() as c:
            return [dict(r) for r in c.execute("SELECT user_id,username,display_name,role,created_at,disabled FROM users ORDER BY username")]

    def trust_view(self, token: str, user_id: str | None = None):
        p = self.identity.resolve(token)
        target = user_id or p.user_id
        if target != p.user_id:
            self._role(token, ("reviewer", "admin"))
        return {"snapshot": self.trust_snapshot_for(target), "history": self.trust.history(target, 100)}

    def recent_trust_events(self, token: str, limit: int = 100):
        self._role(token, ("reviewer", "admin"))
        with self.db.read() as c:
            return [dict(r) for r in c.execute("SELECT event_id,user_id,event_type,ts,severity,verified,negates,request_id FROM trust_events "
                                               "ORDER BY seq DESC LIMIT ?", (limit,))]

    def models_overview(self, token: str):
        self._role(token, ("reviewer", "admin"))
        import json
        out = []
        for m in self.models.list():
            rp = self.models.dir / f"{m['version']}.report.json"
            m["report"] = json.loads(rp.read_text()) if rp.exists() else None
            out.append(m)
        return out
