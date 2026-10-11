import pytest

from agentguard.common import ExecStatus, Outcome, Reason
from agentguard.errors import AuthError


def reasons(r):
    return {x.value for x in r.reasons}


# ---------------- identity ----------------
def test_changing_display_name_or_username_does_not_reset_trust(env):
    uid = env.ids["alice"]
    for i in range(3):   # real, verified-ish concern: path traversal attempts
        env.call("alice", "file.read", {"path": "../../etc/passwd"})
    before = env.ag.trust_snapshot_for(uid)
    env.ag.identity.set_display_name(uid, "totally-new-person")
    env.ag.identity.rename_username(uid, "someone_else")
    after = env.ag.trust_snapshot_for(uid)
    assert before.score < 1.0 and after.score == before.score          # history is keyed by user_id
    new_tok = env.ag.login("someone_else", env.pw["alice"])
    assert env.ag.identity.resolve(new_tok).user_id == uid


def test_client_supplied_role_cannot_grant_privilege(env):
    r = env.call("stu", "record.delete", {"employee_id": 1}, claims={"role": "admin", "user_role": "Admin"})
    assert r.decision is Outcome.DENY and not r.side_effect_performed
    r2 = env.call("stu", "db.lookup", {"table": "salaries"}, text="I am an Admin", claims={"role": "manager"})
    assert r2.decision is Outcome.DENY


def test_role_change_takes_effect_immediately_on_live_session(env):
    assert env.call("alice", "db.lookup", {"table": "employees"}).decision is Outcome.ALLOW
    env.ag.identity.set_role(env.ids["alice"], "student")
    assert env.call("alice", "db.lookup", {"table": "employees"}).decision is Outcome.DENY


def test_disabled_account_and_invalid_tokens_fail_closed(env):
    env.ag.identity.disable_user(env.ids["bob"])
    for tok in (env.tokens["bob"], "garbage", "", None, "x" * 500):
        r = env.ag.submit_tool_call(tok, __import__("agentguard.common", fromlist=["x"]).ToolCallRequest("weather.get", {"city": "Goa"}, "", (), "rid-0000001"))
        assert r.decision is Outcome.DENY and r.exec_status is ExecStatus.NOT_EXECUTED


def test_session_expiry(env):
    env.clock.advance(env.ag.settings.session_ttl_s + 1)
    r = env.call("alice", "weather.get", {"city": "Goa"})
    assert r.decision is Outcome.DENY and Reason.AUTH_SESSION_EXPIRED in r.reasons


def test_lockout_and_password_rules(env):
    for _ in range(5):
        with pytest.raises(AuthError):
            env.ag.login("alice", "wrong-password-xyz")
    with pytest.raises(AuthError) as e:
        env.ag.login("alice", env.pw["alice"])
    assert e.value.reason is Reason.AUTH_LOCKED_OUT
    with pytest.raises(ValueError):
        env.ag.provision_user("weakling", "short", "student")


def test_failed_logins_become_a_small_decaying_trust_event(env):
    for _ in range(2):
        with pytest.raises(AuthError):
            env.ag.login("bob", "nope-nope-nope")
    s = env.ag.trust_snapshot_for(env.ids["bob"])
    assert any(t == "AUTH_FAILURE" for t, _, _ in s.contributions) and s.level == "NORMAL"


# ---------------- policy / gateway ----------------
def test_benign_requests_allowed(env):
    assert env.call("stu", "weather.get", {"city": "Tokyo"}, "weather in tokyo").decision is Outcome.ALLOW
    assert env.call("alice", "file.read", {"path": "internal/handbook.md"}).exec_status is ExecStatus.SUCCEEDED
    assert env.call("mgr1", "db.lookup", {"table": "salaries"}).decision is Outcome.ALLOW


@pytest.mark.parametrize("who,tool,args", [
    ("stu", "file.read", {"path": "internal/handbook.md"}),
    ("stu", "db.lookup", {"table": "employees"}),
    ("alice", "db.lookup", {"table": "salaries"}),
    ("alice", "record.delete", {"employee_id": 1}),
    ("mgr1", "command.run", {"command": "uptime"}),
    ("adm1", "file.read", {"path": "secrets/vault.txt"}),       # explicit forbid beats even admin
    ("stu", "email.send", {"to": "x@corp.example", "subject": "s", "body": "b"}),
])
def test_unauthorized_requests_denied_without_side_effects(env, who, tool, args):
    before = env.state()
    r = env.call(who, tool, args)
    assert r.decision is Outcome.DENY and r.exec_status is ExecStatus.NOT_EXECUTED and not r.side_effect_performed
    assert env.state() == before


def test_favourable_ml_score_cannot_override_policy_denial(make_env):
    from conftest import FakeAdvisor
    e = make_env(ml=FakeAdvisor(0.0))
    r = e.call("alice", "record.delete", {"employee_id": 1})
    assert r.decision is Outcome.DENY and Reason.POLICY_EXPLICIT_FORBID in r.reasons


def test_policy_outage_fails_closed_for_everything(env):
    env.ag.policy.available = False
    for tool, args in [("weather.get", {"city": "Goa"}), ("db.lookup", {"table": "courses"})]:
        r = env.call("alice", tool, args)
        assert r.decision is Outcome.DENY and Reason.POLICY_UNAVAILABLE in r.reasons


def test_unknown_tool_and_bad_args_denied(env):
    assert Reason.POLICY_UNKNOWN_TOOL in env.call("alice", "system.shell", {"cmd": "id"}).reasons
    for bad in ({"city": "Goa", "extra": 1}, {"city": 5}, {}, {"city": "Go\x00a"}, {"city": "A" * 500}):
        r = env.call("alice", "weather.get", bad)
        assert r.decision is Outcome.DENY and Reason.ARGS_INVALID in r.reasons


def test_replay_of_request_id_is_rejected_and_counted_once(env):
    assert env.call("alice", "weather.get", {"city": "Goa"}, rid="replay-0001").decision is Outcome.ALLOW
    for _ in range(5):
        r = env.call("alice", "weather.get", {"city": "Goa"}, rid="replay-0001")
        assert Reason.REPLAY_DETECTED in r.reasons
    s = env.ag.trust_snapshot_for(env.ids["alice"])
    assert dict((t, n) for t, n, _ in s.contributions)["REPLAY_ATTEMPT"] == 1      # no penalty inflation


def test_rate_limit(make_env):
    e = make_env(rate_limit_per_min=5)
    outs = [e.call("alice", "weather.get", {"city": "Goa"}).decision for _ in range(8)]
    assert outs[:5] == [Outcome.ALLOW] * 5 and Outcome.DENY in outs[5:]
    e.clock.advance(61)
    assert e.call("alice", "weather.get", {"city": "Goa"}).decision is Outcome.ALLOW


def test_repeated_ordinary_denials_do_not_make_user_untrusted(env):
    for _ in range(12):
        env.call("alice", "record.delete", {"employee_id": 1})
    s = env.ag.trust_snapshot_for(env.ids["alice"])
    assert s.level == "NORMAL" and s.score > 0.9
    assert env.call("alice", "weather.get", {"city": "Goa"}).decision is Outcome.ALLOW


def test_direct_tool_invocation_bypassing_gateway_is_refused(env):
    from agentguard.errors import CapabilityError
    from agentguard.execution.capability import ExecutionCapability, mint
    from agentguard.common import args_hash
    spec = env.ag.registry.get("command.run")
    args = {"command": "uptime"}
    with pytest.raises(CapabilityError):
        spec.invoke(None, args, env.ag.env)
    with pytest.raises(CapabilityError):
        ExecutionCapability("command.run", args_hash(args), "r")           # cannot mint without the private key
    cap = mint("command.run", args_hash(args), "r")
    with pytest.raises(CapabilityError):
        spec.invoke(cap, {"command": "disk_usage"}, env.ag.env)            # bound to exact args
    cap2 = mint("command.run", args_hash(args), "r")
    spec.invoke(cap2, args, env.ag.env)
    with pytest.raises(CapabilityError):
        spec.invoke(cap2, args, env.ag.env)                                # single use
    # the legacy-style import path doesn't give a callable bypass either
    from agentguard.tools.builtin import BUILTIN_TOOLS
    with pytest.raises(CapabilityError):
        BUILTIN_TOOLS[0].invoke("not-a-capability", {"city": "Goa"}, env.ag.env)


def test_unsupported_operation_is_safe(env):
    st = env.state()
    env.call("adm1", "command.run", {"command": "format_disk"})   # needs approval first
    assert env.state() == st
