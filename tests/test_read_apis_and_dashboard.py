import os
import secrets
import sys
from pathlib import Path

import pytest

from agentguard.errors import AuthError


def test_read_apis_are_authorised_server_side(env):
    env.call("alice", "weather.get", {"city": "Goa"})
    for fn, args in [("audit_search", {}), ("audit_verify", {}), ("list_users", {}), ("recent_trust_events", {}), ("models_overview", {})]:
        with pytest.raises(AuthError):
            getattr(env.ag, fn)(env.tokens["alice"], **args)
    with pytest.raises(AuthError):
        env.ag.pending_approvals(env.tokens["alice"])
    with pytest.raises(AuthError):
        env.ag.trust_view(env.tokens["alice"], env.ids["bob"])        # cannot read someone else's trust state
    assert env.ag.trust_view(env.tokens["alice"])["snapshot"].level == "NORMAL"   # own state is fine
    assert env.ag.audit_search(env.tokens["rev"], limit=5) and env.ag.audit_verify(env.tokens["rev"]) == (True, None)
    assert env.ag.pending_approvals(env.tokens["mgr1"]) == []


def test_dashboard_smoke(tmp_path, monkeypatch):
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest
    monkeypatch.setenv("AGENTGUARD_DATA_DIR", str(tmp_path)); monkeypatch.setenv("AGENTGUARD_ENV", "dev")
    from agentguard.api import AgentGuard
    from agentguard.config import Settings
    ag = AgentGuard(Settings.from_env())
    pw = secrets.token_urlsafe(14); ag.provision_user("emp", pw, "employee"); ag.provision_user("rev", pw, "reviewer")
    app = str(Path(__file__).resolve().parents[1] / "dashboard" / "app.py")
    for user, expect_admin_pages in (("emp", False), ("rev", True)):
        at = AppTest.from_file(app, default_timeout=60).run()
        at.text_input[0].set_value(user); at.text_input[1].set_value(pw); at.button[0].click(); at.run()
        pages = at.sidebar.radio[0].options
        assert ("Audit & incidents" in pages) is expect_admin_pages
        for pg in pages:
            at.sidebar.radio[0].set_value(pg).run()
            assert not at.exception, (user, pg)
