from __future__ import annotations

import secrets
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..api import AgentGuard
from ..clock import FakeClock
from ..common import ContentItem, ToolCallRequest
from ..config import Settings
from ..errors import ModelUnavailable
from ..tools.sandbox import snapshot

LATENCIES: list[float] = []


class Advisor:
    version = "bench-fake"

    def __init__(self, score=0.05, available=True):
        self._s, self.available = score, available

    def score(self, text, *, tool, sensitivity, source):
        if not self.available:
            raise ModelUnavailable("unavailable")
        return self._s


class BenchEnv:
    def __init__(self, ml="healthy", **kw):
        self.tmp = Path(tempfile.mkdtemp(prefix="agbench-"))
        self.clock = FakeClock()
        base = dict(env="test", data_dir=self.tmp, hmac_key=secrets.token_bytes(32), scrypt_n=2 ** 10)
        base.update(kw)
        adv = Advisor() if ml == "healthy" else Advisor(available=False) if ml == "down" else None
        self.ag = AgentGuard(Settings(**base), clock=self.clock, ml=adv)
        self.pw, self.tok, self.ids = {}, {}, {}
        for n, r in [("alice", "employee"), ("bob", "employee"), ("stu", "student"), ("mgr1", "manager"), ("mgr2", "manager"),
                     ("adm1", "admin"), ("adm2", "admin"), ("rev", "reviewer")]:
            self.pw[n] = secrets.token_urlsafe(16)
            self.ids[n] = self.ag.provision_user(n, self.pw[n], r)
            self.tok[n] = self.ag.login(n, self.pw[n])
        self.last_uid: str | None = None
        self.last_rid: str | None = None

    def call(self, who, tool, args=None, text="", untrusted=(), rid=None, claims=None):
        self.last_uid = self.ids.get(who)
        self.last_rid = rid or uuid.uuid4().hex
        t0 = time.perf_counter()
        r = self.ag.submit_tool_call(self.tok.get(who, who), ToolCallRequest(
            tool, args or {}, text, tuple(ContentItem(s, t) for s, t in untrusted), self.last_rid, claims or {}))
        LATENCIES.append((time.perf_counter() - t0) * 1000)
        return r

    def state(self):
        return snapshot(self.ag.env.sandbox_db)


@dataclass
class Observed:
    decision: str
    side_effect: bool = False
    leaked: bool = False
    ok: bool = True
    note: str = ""


@dataclass
class Scenario:
    id: str
    category: int
    title: str
    initial: str
    request: str
    expected: str                    # ALLOW | DENY | REQUIRE_APPROVAL | BLOCKED
    side_effect_allowed: bool
    audit: str | None                # expected audit event_type
    malicious: bool                  # attack scenario (counts toward attack-success-rate)
    unauthorized: bool               # attempts something the principal must not do
    fn: Callable[[BenchEnv], Observed]
    env_kw: dict = field(default_factory=dict)


CATEGORIES = {1: "Benign allowed", 2: "Unauthorized denied", 3: "Display-name/username change", 4: "Client-side role claim",
              5: "Direct prompt injection", 6: "Indirect prompt injection", 7: "Sensitive-data disclosure", 8: "File access / traversal",
              9: "Malicious tool arguments", 10: "Rate / behavioural anomaly", 11: "Repeated false-positive denials",
              12: "Missing/stale/corrupt model", 13: "Policy/DB/audit failure", 14: "Approval expiry / modification",
              15: "Replay / duplicates", 16: "Tool-output manipulation", 17: "Concurrency", 18: "UI/gateway bypass",
              19: "Unsupported operations", 20: "Legit requests with suspicious words"}
