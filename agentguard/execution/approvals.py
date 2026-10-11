"""Human approval bound to the exact operation.

An approval binds: requester, tool, action, resource, canonical hash of validated arguments,
original request id, policy version and expiry. The row is HMAC-signed so out-of-band edits to the
database (e.g. flipping status to APPROVED) are detected. Approval is single-use (atomic CAS).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from typing import Any

from ..clock import Clock
from ..common import Reason, canonical_json
from ..config import Settings
from ..db import Database
from ..errors import ApprovalError


def binding_hash(requester_id: str, tool: str, action: str, resource: str, args_hash: str,
                 request_id: str, policy_version: str) -> str:
    return hashlib.sha256(canonical_json({
        "requester": requester_id, "tool": tool, "action": action, "resource": resource,
        "args": args_hash, "request": request_id, "policy": policy_version}).encode()).hexdigest()


class ApprovalService:
    def __init__(self, db: Database, clock: Clock, settings: Settings):
        self.db, self.clock, self.s = db, clock, settings

    def _sign(self, row: dict[str, Any]) -> str:
        msg = canonical_json({k: row[k] for k in ("approval_id", "binding_hash", "status", "approver_id",
                                                  "decided_at", "expires_at")})
        return hmac.new(self.s.hmac_key, msg.encode(), hashlib.sha256).hexdigest()

    def create(self, *, requester_id: str, tool: str, action: str, resource: str, args_hash: str,
               request_id: str, policy_version: str, risk_flags: list[str]) -> str:
        aid = str(uuid.uuid4())
        now = self.clock.now()
        row = {"approval_id": aid, "binding_hash": binding_hash(requester_id, tool, action, resource, args_hash,
                                                                 request_id, policy_version),
               "status": "PENDING", "approver_id": None, "decided_at": None, "expires_at": now + self.s.approval_ttl_s}
        with self.db.tx() as c:
            c.execute("INSERT INTO approvals(approval_id,request_id,requester_id,tool,action,resource,args_hash,policy_version,"
                      "binding_hash,created_at,expires_at,status,risk_flags,signature) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (aid, request_id, requester_id, tool, action, resource, args_hash, policy_version,
                       row["binding_hash"], now, row["expires_at"], "PENDING", json.dumps(risk_flags), self._sign(row)))
        return aid

    def _load(self, c, approval_id: str) -> dict:
        r = c.execute("SELECT * FROM approvals WHERE approval_id=?", (approval_id,)).fetchone()
        if r is None:
            raise ApprovalError(Reason.APPROVAL_NOT_FOUND)
        d = dict(r)
        if not hmac.compare_digest(d["signature"], self._sign(d)):
            raise ApprovalError(Reason.APPROVAL_TAMPERED)
        return d

    def get(self, approval_id: str) -> dict:
        with self.db.read() as c:
            return self._load(c, approval_id)

    def pending(self) -> list[dict]:
        with self.db.read() as c:
            return [dict(r) for r in c.execute(
                "SELECT approval_id,request_id,requester_id,tool,action,resource,created_at,expires_at,risk_flags "
                "FROM approvals WHERE status='PENDING' AND expires_at>? ORDER BY created_at", (self.clock.now(),))]

    def decide(self, *, approval_id: str, reviewer_id: str, reviewer_role: str, approve: bool,
               can_approve: bool, comment: str = "") -> dict:
        with self.db.tx() as c:
            d = self._load(c, approval_id)
            if d["status"] != "PENDING":
                raise ApprovalError(Reason.APPROVAL_ALREADY_USED if d["status"] == "CONSUMED" else Reason.APPROVAL_NOT_APPROVED)
            if d["expires_at"] <= self.clock.now():
                d.update(status="EXPIRED"); d["signature"] = self._sign(d)
                c.execute("UPDATE approvals SET status=?,signature=? WHERE approval_id=?", ("EXPIRED", d["signature"], approval_id))
                c.execute("COMMIT"); c.execute("BEGIN IMMEDIATE")
                raise ApprovalError(Reason.APPROVAL_EXPIRED)
            if reviewer_id == d["requester_id"]:
                raise ApprovalError(Reason.APPROVAL_SELF_APPROVAL)
            if not can_approve:
                raise ApprovalError(Reason.APPROVAL_UNAUTHORIZED_REVIEWER)
            d.update(status="APPROVED" if approve else "REJECTED", approver_id=reviewer_id, decided_at=self.clock.now())
            d["signature"] = self._sign(d)
            c.execute("UPDATE approvals SET status=?,approver_id=?,decided_at=?,comment=?,signature=? WHERE approval_id=? AND status='PENDING'",
                      (d["status"], reviewer_id, d["decided_at"], comment[:200], d["signature"], approval_id))
            return d

    def consume(self, *, approval_id: str, requester_id: str, tool: str, action: str, resource: str,
                args_hash: str, policy_version: str) -> dict:
        """Validate the approval against the ACTUAL call being executed, then burn it atomically."""
        with self.db.tx() as c:
            d = self._load(c, approval_id)
            if d["requester_id"] != requester_id:
                raise ApprovalError(Reason.APPROVAL_WRONG_REQUESTER)
            if d["status"] == "CONSUMED":
                raise ApprovalError(Reason.APPROVAL_ALREADY_USED)
            if d["status"] == "REJECTED" or d["status"] == "PENDING":
                raise ApprovalError(Reason.APPROVAL_NOT_APPROVED if d["status"] == "REJECTED" else Reason.APPROVAL_PENDING)
            if d["status"] == "EXPIRED" or d["expires_at"] <= self.clock.now():
                raise ApprovalError(Reason.APPROVAL_EXPIRED)
            if d["policy_version"] != policy_version:
                raise ApprovalError(Reason.POLICY_VERSION_CHANGED)
            expect = binding_hash(requester_id, tool, action, resource, args_hash, d["request_id"], policy_version)
            if not hmac.compare_digest(expect, d["binding_hash"]):
                raise ApprovalError(Reason.APPROVAL_BINDING_MISMATCH)
            d["status"] = "CONSUMED"
            sig = self._sign(d)
            cur = c.execute("UPDATE approvals SET status='CONSUMED',signature=? WHERE approval_id=? AND status='APPROVED'",
                            (sig, approval_id))
            if cur.rowcount != 1:                       # lost a race: someone else consumed it first
                raise ApprovalError(Reason.APPROVAL_ALREADY_USED)
            return d
