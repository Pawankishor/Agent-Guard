from __future__ import annotations

from .common import Reason


class AgentGuardError(Exception):
    pass


class ConfigError(AgentGuardError):
    pass


class AuthError(AgentGuardError):
    def __init__(self, reason: Reason, msg: str = ""):
        super().__init__(msg or reason.value)
        self.reason = reason


class ArgumentError(AgentGuardError):
    def __init__(self, msg: str, field: str | None = None, reason: Reason = Reason.ARGS_INVALID):
        super().__init__(msg)
        self.field = field
        self.reason = reason


class PathViolation(ArgumentError):
    def __init__(self, msg: str, field: str | None = "path"):
        super().__init__(msg, field, Reason.PATH_TRAVERSAL)


class PolicyUnavailable(AgentGuardError):
    pass


class CapabilityError(AgentGuardError):
    pass


class ToolError(AgentGuardError):
    """Expected, safe-to-show tool failure (e.g. NOT_FOUND)."""
    def __init__(self, code: str, msg: str = ""):
        super().__init__(msg or code)
        self.code = code


class UnsupportedOperation(ToolError):
    def __init__(self, msg: str = "unsupported operation"):
        super().__init__("UNSUPPORTED", msg)


class ToolTimeout(AgentGuardError):
    pass


class ApprovalError(AgentGuardError):
    def __init__(self, reason: Reason, msg: str = ""):
        super().__init__(msg or reason.value)
        self.reason = reason


class ModelUnavailable(AgentGuardError):
    pass


class AuditUnavailable(AgentGuardError):
    pass
