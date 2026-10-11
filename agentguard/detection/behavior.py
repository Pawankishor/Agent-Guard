"""Layer 3: behavioural signals from the principal's own recent activity (rate bursts, tool probing)."""
from __future__ import annotations

from ..common import Signal
from ..trust.engine import TrustEngine


class BehaviorDetector:
    name, version = "behavior", "1.0"

    def __init__(self, trust: TrustEngine, rate_limit_per_min: int):
        self.trust, self.limit = trust, rate_limit_per_min

    def signals_for(self, user_id: str) -> list[Signal]:
        out: list[Signal] = []
        n = self.trust.requests_in_window(user_id, 60.0)
        if n >= 0.7 * self.limit:
            out.append(Signal("behavior:burst", "rate", min(0.8, 0.3 + 0.5 * n / self.limit), "system", self.name,
                              self.version, ("BURST",), f"{n}/min"))
        k = self.trust.distinct_denied_tools(user_id, 600.0)
        if k >= 4:
            out.append(Signal("behavior:tool_probing", "probing", min(0.7, 0.3 + 0.1 * k), "system", self.name,
                              self.version, ("TOOL_PROBING",), f"{k} distinct denied tools/10min"))
        return out
