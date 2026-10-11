"""Single-use execution capabilities.

A tool handler can only run when `ToolSpec.invoke` is given a capability that (a) was minted by this
module's private `mint()` and (b) is bound to the exact tool + canonical-args hash and unused.
Only `execution.gateway` imports `mint`. This is DEFENCE-IN-DEPTH against accidental or lazy bypass
(e.g. UI code importing a tool function). It is NOT a sandbox: hostile code in the same Python
process can always reach private names. Real isolation = separate process/container (see docs).
"""
from __future__ import annotations

from ..errors import CapabilityError

_MINT_KEY = object()


class ExecutionCapability:
    __slots__ = ("_tool", "_args_hash", "_request_id", "_used")

    def __init__(self, tool: str, args_hash: str, request_id: str, *, _key: object = None):
        if _key is not _MINT_KEY:
            raise CapabilityError("capabilities can only be minted by the execution gateway")
        self._tool, self._args_hash, self._request_id, self._used = tool, args_hash, request_id, False

    def consume(self, tool: str, args_hash: str) -> None:
        if self._used:
            raise CapabilityError("capability already used")
        if tool != self._tool or args_hash != self._args_hash:
            raise CapabilityError("capability does not match tool/arguments")
        self._used = True

    @property
    def request_id(self) -> str:
        return self._request_id


def mint(tool: str, args_hash: str, request_id: str) -> ExecutionCapability:
    return ExecutionCapability(tool, args_hash, request_id, _key=_MINT_KEY)
