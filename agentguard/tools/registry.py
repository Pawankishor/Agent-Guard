from __future__ import annotations

from .base import ToolSpec


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._tools:
            raise ValueError(f"tool {spec.name} already registered")
        if "." not in spec.name:
            raise ValueError("tool name must be '<domain>.<action>'")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name) if isinstance(name, str) else None

    def names(self) -> list[str]:
        return sorted(self._tools)


def default_registry() -> ToolRegistry:
    from .builtin import BUILTIN_TOOLS
    r = ToolRegistry()
    for t in BUILTIN_TOOLS:
        r.register(t)
    return r
