"""Context trust state per *verified identity* (immutable user_id).

Design rules (all unit-tested):
* Trust is an ESTIMATE used only to raise scrutiny. It never grants access and is not proof of malice.
* Distinct event types with their own weight, half-life and per-type cap. An ordinary policy DENY is
  nearly weightless and capped, so honest users who keep hitting permission walls are not "punished".
* Exponential time decay: nothing automated is permanent. Only reviewer-VERIFIED events decay slowly.
* Duplicate/replayed events are ignored via a unique dedupe key (INSERT OR IGNORE).
* A reviewer can negate an event (false positive); negated events contribute zero.
* Pure/deterministic: score = f(events, now). The clock is injected.
* Missing/future-dated/unknown-type events => data_quality flags; DB failure => `unavailable`.
  Callers must treat non-OK data quality as "unknown", never as "clean".
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field

from ..clock import Clock
from ..db import Database


@dataclass(frozen=True)
class EventSpec:
    weight: float        # penalty contributed by one severity=1.0 event at age 0
    half_life_s: float
    cap: float           # max total penalty from this event type


H, D = 3600.0, 86400.0
EVENT_SPECS: dict[str, EventSpec] = {
    "AUTH_FAILURE": EventSpec(0.06, 1 * H, 0.30),
    "POLICY_DENIAL": EventSpec(0.01, 1 * D, 0.08),         # ordinary denial: deliberately tiny + capped
    "MALFORMED_REQUEST": EventSpec(0.01, 6 * H, 0.05),
    "INJECTION_SUSPECTED": EventSpec(0.15, 3 * D, 0.40),   # automated, unverified
    "PATH_VIOLATION": EventSpec(0.15, 3 * D, 0.40),
    "RATE_ANOMALY": EventSpec(0.05, 2 * H, 0.20),
    "REPLAY_ATTEMPT": EventSpec(0.05, 1 * D, 0.20),
    "APPROVAL_TAMPER_ATTEMPT": EventSpec(0.20, 7 * D, 0.50),
    "SECRET_REQUEST": EventSpec(0.08, 2 * D, 0.30),
    "CONFIRMED_MALICIOUS": EventSpec(0.60, 30 * D, 1.00),  # reviewer-verified only
    "FALSE_POSITIVE_CLEARED": EventSpec(0.0, 1.0, 0.0),    # a negation marker, never a penalty itself
}
VERIFIED_ONLY = {"CONFIRMED_MALICIOUS"}


@dataclass(frozen=True)
class TrustSnapshot:
    score: float                      # 1.0 = no concerns, 0.0 = max concern. An estimate, not a verdict.
    level: str                        # NORMAL | WATCH | LOW | RESTRICTED | UNKNOWN
    data_quality: str                 # OK | INCONSISTENT | UNAVAILABLE
    contributions: tuple[tuple[str, int, float], ...] = ()    # (event_type, n_events, penalty)
    new_account: bool = False

    @property
    def usable(self) -> bool:
        return self.data_quality == "OK"

    def explain(self) -> list[str]:
        if not self.contributions:
            return ["no relevant history"]
        return [f"{t}: {n} event(s), penalty {p:.3f}" for t, n, p in self.contributions]


@dataclass(frozen=True)
class TrustTransition:
    event_type: str
    event_id: str | None
    duplicate: bool
    before: float
    after: float

    def as_dict(self) -> dict:
        return {"event_type": self.event_type, "event_id": self.event_id, "duplicate": self.duplicate,
                "score_before": round(self.before, 4), "score_after": round(self.after, 4)}


class TrustEngine:
    def __init__(self, db: Database, clock: Clock, *, skew_s: int = 300, horizon_days: int = 120,
                 new_account_s: float = 24 * 3600):
        self.db, self.clock, self.skew_s = db, clock, skew_s
        self.horizon_s = horizon_days * D
        self.new_account_s = new_account_s
        self.fail_for_testing = False

    # ---- state ------------------------------------------------------------------------------
    def snapshot(self, user_id: str, *, account_created_at: float | None = None) -> TrustSnapshot:
        now = self.clock.now()
        new_acct = account_created_at is not None and (now - account_created_at) < self.new_account_s
        try:
            if self.fail_for_testing:
                raise RuntimeError("trust store unavailable (simulated)")
            with self.db.read() as c:
                rows = c.execute("SELECT event_id,event_type,ts,severity,verified,negates FROM trust_events "
                                 "WHERE user_id=? AND ts>? ORDER BY seq", (user_id, now - self.horizon_s)).fetchall()
        except Exception:
            return TrustSnapshot(0.5, "UNKNOWN", "UNAVAILABLE", (), new_acct)
        quality = "OK"
        negated = {r["negates"] for r in rows if r["negates"]}
        per_type: dict[str, list[float]] = {}
        for r in rows:
            spec = EVENT_SPECS.get(r["event_type"])
            if spec is None or r["ts"] > now + self.skew_s or not (0.0 <= r["severity"] <= 1.0):
                quality = "INCONSISTENT"      # unknown type / future-dated / bad severity: ignore + flag
                continue
            if r["event_type"] in VERIFIED_ONLY and not r["verified"]:
                quality = "INCONSISTENT"      # an unverified claim of a verified-only type is suspicious
                continue
            if r["event_id"] in negated or spec.weight == 0.0:
                continue
            age = max(0.0, now - r["ts"])
            per_type.setdefault(r["event_type"], []).append(spec.weight * r["severity"] * 0.5 ** (age / spec.half_life_s))
        contribs, total = [], 0.0
        for t, vals in sorted(per_type.items()):
            pen = min(sum(vals), EVENT_SPECS[t].cap)
            contribs.append((t, len(vals), pen))
            total += pen
        score = max(0.0, 1.0 - total)
        restricted = any(t == "CONFIRMED_MALICIOUS" and p >= 0.3 for t, _, p in contribs)
        level = ("RESTRICTED" if restricted else "NORMAL" if score >= 0.75 else "WATCH" if score >= 0.5 else "LOW")
        return TrustSnapshot(score, level, quality, tuple(contribs), new_acct)

    # ---- updates ----------------------------------------------------------------------------
    def record(self, user_id: str, event_type: str, *, severity: float = 1.0, request_id: str | None = None,
               detail: str = "", dedupe_extra: str = "", verified: bool = False,
               negates: str | None = None) -> TrustTransition:
        """Append a trust event. Replays are no-ops (same dedupe key). Returns before/after scores."""
        if event_type not in EVENT_SPECS:
            raise ValueError(f"unknown trust event type {event_type}")
        if event_type in VERIFIED_ONLY and not verified:
            raise ValueError(f"{event_type} can only be recorded as verified (human review)")
        severity = max(0.0, min(1.0, float(severity)))
        before = self.snapshot(user_id).score
        key = hashlib.sha256("|".join([user_id, event_type, request_id or "", dedupe_extra, negates or ""]).encode()).hexdigest()
        eid = str(uuid.uuid4())
        try:
            with self.db.tx() as c:
                cur = c.execute(
                    "INSERT OR IGNORE INTO trust_events(event_id,dedupe_key,user_id,event_type,ts,severity,verified,negates,request_id,detail)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (eid, key, user_id, event_type, self.clock.now(), severity, int(verified), negates, request_id, detail[:200]))
                dup = cur.rowcount == 0
        except Exception:
            return TrustTransition(event_type, None, False, before, before)   # caller treats as unavailable
        after = self.snapshot(user_id).score
        return TrustTransition(event_type, None if dup else eid, dup, before, after)

    def history(self, user_id: str, limit: int = 200) -> list[dict]:
        with self.db.read() as c:
            return [dict(r) for r in c.execute(
                "SELECT event_id,event_type,ts,severity,verified,negates,request_id,detail FROM trust_events "
                "WHERE user_id=? ORDER BY seq DESC LIMIT ?", (user_id, limit))]

    # ---- request-level behaviour helpers ------------------------------------------------------
    def claim_request(self, user_id: str, request_id: str) -> bool:
        """Replay protection: a (user, request_id) pair can be processed once. False => replay."""
        with self.db.tx() as c:
            cur = c.execute("INSERT OR IGNORE INTO seen_requests(principal_id,request_id,ts) VALUES(?,?,?)",
                            (user_id, request_id, self.clock.now()))
            return cur.rowcount == 1

    def requests_in_window(self, user_id: str, window_s: float = 60.0) -> int:
        with self.db.read() as c:
            return c.execute("SELECT COUNT(*) FROM seen_requests WHERE principal_id=? AND ts>?",
                             (user_id, self.clock.now() - window_s)).fetchone()[0]

    def distinct_denied_tools(self, user_id: str, window_s: float = 600.0) -> int:
        with self.db.read() as c:
            return c.execute("SELECT COUNT(DISTINCT detail) FROM trust_events WHERE user_id=? AND event_type='POLICY_DENIAL' AND ts>?",
                             (user_id, self.clock.now() - window_s)).fetchone()[0]
