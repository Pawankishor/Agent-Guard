"""Interface between the runtime and the ML layer. The runtime only ever sees an advisory score or
'unavailable'. A model has no authority: see risk.assess for how the score is (mis)trusted."""
from __future__ import annotations

from typing import Protocol

from ..common import Sensitivity


class MlAdvisor(Protocol):
    available: bool
    version: str | None

    def score(self, text: str, *, tool: str, sensitivity: Sensitivity, source: str) -> float:
        """Return calibrated P(suspicious) in [0,1]. Raise ModelUnavailable on ANY problem."""
        ...


class NullAdvisor:
    """No model deployed. Protected calls escalate (settings.ml_required_for_protected)."""
    available = False
    version = None

    def score(self, text, *, tool, sensitivity, source):  # noqa: D401
        from ..errors import ModelUnavailable
        raise ModelUnavailable("no model deployed")
