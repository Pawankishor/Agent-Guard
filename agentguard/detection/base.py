"""Detector interface. Detectors produce Signals; they have NO authority to grant permissions.
The type system enforces this: a Signal carries a severity, nothing else."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

from ..common import ContentItem, Signal


@dataclass(frozen=True)
class DetectionInput:
    user_text: str
    untrusted: tuple[ContentItem, ...]
    arguments: Mapping[str, Any]
    tool: str
    side_effect: bool = False


@runtime_checkable
class Detector(Protocol):
    name: str
    version: str

    def detect(self, inp: DetectionInput) -> Sequence[Signal]: ...


class DetectorSuite:
    """Runs every detector; a crashing detector yields an `error` signal (fail-safe), never silence."""

    def __init__(self, detectors: Sequence[Detector]):
        self.detectors = list(detectors)

    @property
    def versions(self) -> dict[str, str]:
        return {d.name: d.version for d in self.detectors}

    def run(self, inp: DetectionInput) -> list[Signal]:
        out: list[Signal] = []
        for d in self.detectors:
            try:
                out.extend(d.detect(inp))
            except Exception as e:  # noqa: BLE001
                out.append(Signal("detector_error", "operational", 0.0, "system", d.name, d.version,
                                  (type(e).__name__,), "", error=True))
        return out
