import secrets
import uuid

import pytest

from agentguard.api import AgentGuard
from agentguard.clock import FakeClock
from agentguard.common import ContentItem, Sensitivity, ToolCallRequest
from agentguard.config import Settings
from agentguard.errors import ModelUnavailable
from agentguard.tools.sandbox import snapshot


class FakeAdvisor:
    """Stand-in model: fixed score, or unavailable. Used to prove ML has no authority."""
    version = "fake-1"

    def __init__(self, score=0.05, available=True):
        self._s, self.available = score, available

    def score(self, text, *, tool, sensitivity, source):
        if not self.available:
            raise ModelUnavailable("fake outage")
        return self._s


class Env:
    def __init__(self, tmp_path, ml=None, **settings_kw):
        self.clock = FakeClock()
        kw = dict(env="test", data_dir=tmp_path, hmac_key=secrets.token_bytes(32), scrypt_n=2 ** 10)
        kw.update(settings_kw)
        self.ag = AgentGuard(Settings(**kw), clock=self.clock, ml=(None if ml == 'registry' else ml) if ml is not None else FakeAdvisor())
        self.pw, self.tokens, self.ids = {}, {}, {}
        for name, role in [("alice", "employee"), ("bob", "employee"), ("stu", "student"), ("mgr1", "manager"),
                           ("mgr2", "manager"), ("adm1", "admin"), ("adm2", "admin"), ("rev", "reviewer")]:
            self.user(name, role)

    def user(self, name, role):
        pw = secrets.token_urlsafe(16)
        self.ids[name] = self.ag.provision_user(name, pw, role)
        self.pw[name] = pw
        self.tokens[name] = self.ag.login(name, pw)
        return self.tokens[name]

    def call(self, who, tool, args=None, text="", untrusted=(), rid=None, claims=None):
        tok = self.tokens.get(who, who)
        return self.ag.submit_tool_call(tok, ToolCallRequest(
            tool, args or {}, text, tuple(ContentItem(s, t) for s, t in untrusted),
            rid or uuid.uuid4().hex, claims or {}))

    def state(self):
        return snapshot(self.ag.env.sandbox_db)


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


@pytest.fixture
def make_env(tmp_path):
    def _mk(**kw):
        return Env(tmp_path / uuid.uuid4().hex[:6], **kw)
    return _mk
