"""Structured, append-only, tamper-evident audit log.

* Append-only at the DB level (triggers abort UPDATE/DELETE).
* Each record carries HMAC-SHA256(key, prev_hash || canonical_payload): a hash chain. Anyone who can
  edit the file but lacks the key cannot forge a consistent chain; `verify_chain()` finds the first
  broken link. This is TAMPER-EVIDENT, not tamper-proof: ship records to external WORM storage in
  production (see docs/ARCHITECTURE.md).
* Appends run in BEGIN IMMEDIATE transactions, so concurrent writers serialise and the chain stays valid.
* Secrets are redacted and long strings truncated before storage; raw request text is never stored.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from typing import Any, Iterable, Sequence

from ..clock import Clock
from ..common import canonical_json
from ..db import Database
from ..detection.leakage import redact_obj

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, db: Database, clock: Clock, hmac_key: bytes):
        self.db, self.clock, self._key = db, clock, hmac_key
        self.fail_for_testing = False   # simulate audit-store outage in tests/benchmarks

    def _mac(self, prev: str, payload_json: str) -> str:
        return hmac.new(self._key, (prev + payload_json).encode(), hashlib.sha256).hexdigest()

    def record(self, event_type: str, *, principal_id: str | None = None, session_id: str | None = None,
               request_id: str | None = None, tool: str | None = None, action: str | None = None,
               resource_class: str | None = None, outcome: str | None = None, outcome_class: str | None = None,
               reasons: Iterable[Any] = (), signals: Sequence[dict] = (), trust_transition: dict | None = None,
               detector_versions: dict | None = None, model_version: str | None = None,
               approval_status: str | None = None, exec_status: str | None = None,
               details: dict | None = None) -> str:
        if self.fail_for_testing:
            from ..errors import AuditUnavailable
            raise AuditUnavailable("audit store unavailable (simulated)")
        event_id = str(uuid.uuid4())
        ts = self.clock.now()
        payload = {
            "event_id": event_id, "ts": ts, "event_type": event_type, "principal_id": principal_id,
            "session_id": session_id, "request_id": request_id, "tool": tool, "action": action,
            "resource_class": resource_class, "outcome": outcome, "outcome_class": outcome_class,
            "reason_codes": [getattr(r, "value", str(r)) for r in reasons],
            "signals": redact_obj(list(signals)), "trust_transition": redact_obj(trust_transition),
            "detector_versions": detector_versions or {}, "model_version": model_version,
            "approval_status": approval_status, "exec_status": exec_status, "details": redact_obj(details or {}),
        }
        pj = canonical_json(payload)
        with self.db.tx() as c:
            row = c.execute("SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
            prev = row["hash"] if row else GENESIS
            c.execute(
                "INSERT INTO audit_events(event_id,ts,event_type,principal_id,session_id,request_id,tool,action,"
                "resource_class,outcome,outcome_class,approval_status,exec_status,payload_json,prev_hash,hash)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (event_id, ts, event_type, principal_id, session_id, request_id, tool, action, resource_class,
                 outcome, outcome_class, approval_status, exec_status, pj, prev, self._mac(prev, pj)))
        return event_id

    def verify_chain(self) -> tuple[bool, int | None]:
        """Recompute the chain. Returns (ok, first_bad_seq)."""
        prev = GENESIS
        with self.db.read() as c:
            for r in c.execute("SELECT seq,event_id,event_type,principal_id,request_id,payload_json,prev_hash,hash "
                               "FROM audit_events ORDER BY seq"):
                p = json.loads(r["payload_json"])
                if (r["prev_hash"] != prev or not hmac.compare_digest(r["hash"], self._mac(prev, r["payload_json"]))
                        or p["event_id"] != r["event_id"] or p["event_type"] != r["event_type"]
                        or p["principal_id"] != r["principal_id"] or p["request_id"] != r["request_id"]):
                    return False, r["seq"]
                prev = r["hash"]
        return True, None

    def search(self, *, event_type: str | None = None, principal_id: str | None = None,
               tool: str | None = None, outcome: str | None = None, request_id: str | None = None,
               since: float | None = None, until: float | None = None, limit: int = 200) -> list[dict]:
        q, a = "SELECT payload_json FROM audit_events WHERE 1=1", []
        for col, val in (("event_type", event_type), ("principal_id", principal_id), ("tool", tool),
                         ("outcome", outcome), ("request_id", request_id)):
            if val is not None:
                q += f" AND {col}=?"      # column names are fixed literals above; values are parameters
                a.append(val)
        if since is not None:
            q += " AND ts>=?"; a.append(since)
        if until is not None:
            q += " AND ts<=?"; a.append(until)
        q += " ORDER BY seq DESC LIMIT ?"
        a.append(max(1, min(int(limit), 1000)))
        with self.db.read() as c:
            return [json.loads(r["payload_json"]) for r in c.execute(q, a)]

    def count(self) -> int:
        with self.db.read() as c:
            return c.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
