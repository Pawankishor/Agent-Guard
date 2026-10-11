from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from ..clock import Clock
from ..errors import CapabilityError, ToolTimeout
from ..execution.capability import ExecutionCapability
from ..common import Resource, RiskClass, args_hash
from .schema import Field  # noqa: F401  (re-exported)

_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="agentguard-tool")


@dataclass
class ToolEnv:
    sandbox_root: Path
    sandbox_db: Path
    weather: Any
    internal_domains: tuple[str, ...]
    clock: Clock
    max_output_bytes: int = 65536


@dataclass(frozen=True)
class ToolSpec:
    name: str                                   # "<domain>.<action>", e.g. "record.update"
    description: str
    fields: tuple[Field, ...]
    risk_class: RiskClass
    side_effect: bool
    reversible: bool
    resolver: Callable[[Mapping[str, Any], ToolEnv], Resource]   # args -> classified target resource
    handler: Callable[[Mapping[str, Any], ToolEnv], Any]
    timeout_s: float = 5.0

    @property
    def action(self) -> str:
        return self.name.split(".", 1)[1]

    def invoke(self, capability: ExecutionCapability, args: Mapping[str, Any], env: ToolEnv) -> Any:
        """Run the handler. Refuses to run without a valid, matching, unused gateway capability."""
        if not isinstance(capability, ExecutionCapability):
            raise CapabilityError("direct tool invocation is not permitted; go through the gateway")
        capability.consume(self.name, args_hash(args))
        fut = _POOL.submit(self.handler, dict(args), env)
        try:
            return fut.result(timeout=self.timeout_s)
        except concurrent.futures.TimeoutError as e:
            fut.cancel()
            # A running thread cannot be killed. Outcome is UNKNOWN for side-effecting tools; see docs.
            raise ToolTimeout(f"{self.name} exceeded {self.timeout_s}s") from e
