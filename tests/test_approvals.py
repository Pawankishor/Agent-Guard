import threading
import uuid

import pytest

from agentguard.common import ContentItem, ExecStatus, Outcome, Reason, ToolCallRequest

UPD = {"employee_id": 2, "field": "phone", "value": "555-9999"}


def req(rid=None, args=None, text="update employee 2 phone"):
    return ToolCallRequest("record.update", args or dict(UPD), text, (), rid or uuid.uuid4().hex)


def pending(env):
    r = env.ag.submit_tool_call(env.tokens["alice"], req("orig-req-0001"))
    assert r.decision is Outcome.REQUIRE_APPROVAL and r.approval_id and not r.side_effect_performed
    return r.approval_id


def test_happy_path_requires_approval_then_executes_once(env):
    before = env.state()
    aid = pending(env)
    assert env.state() == before                                  # nothing happened while pending
    assert env.ag.decide_approval(env.tokens["mgr1"], aid, True)["ok"]
    r = env.ag.execute_approved(env.tokens["alice"], aid, req())
    assert r.exec_status is ExecStatus.SUCCEEDED and r.side_effect_performed
    assert any(row[0] == 2 and row[3] == "555-9999" for row in env.state()["employees"])
    r2 = env.ag.execute_approved(env.tokens["alice"], aid, req())      # reuse
    assert r2.decision is Outcome.DENY and Reason.APPROVAL_ALREADY_USED in r2.reasons


def test_not_executable_before_decision_or_when_rejected(env):
    aid = pending(env)
    assert Reason.APPROVAL_PENDING in env.ag.execute_approved(env.tokens["alice"], aid, req()).reasons
    env.ag.decide_approval(env.tokens["mgr1"], aid, False)
    r = env.ag.execute_approved(env.tokens["alice"], aid, req())
    assert r.decision is Outcome.DENY and not r.side_effect_performed


@pytest.mark.parametrize("mutate", [
    {"value": "555-0000"}, {"employee_id": 3}, {"field": "department", "value": "CS"}])
def test_modifying_arguments_after_approval_is_rejected(env, mutate):
    aid = pending(env)
    env.ag.decide_approval(env.tokens["mgr1"], aid, True)
    before = env.state()
    r = env.ag.execute_approved(env.tokens["alice"], aid, req(args={**UPD, **mutate}))
    assert r.decision is Outcome.DENY and Reason.APPROVAL_BINDING_MISMATCH in r.reasons
    assert env.state() == before
    s = env.ag.trust_snapshot_for(env.ids["alice"])
    assert any(t == "APPROVAL_TAMPER_ATTEMPT" for t, _, _ in s.contributions)


def test_approval_for_one_tool_cannot_run_another(env):
    aid = pending(env)
    env.ag.decide_approval(env.tokens["mgr1"], aid, True)
    r = env.ag.execute_approved(env.tokens["alice"], aid, ToolCallRequest("email.send", {"to": "x@evil.test", "subject": "s", "body": "b"}, "", (), uuid.uuid4().hex))
    assert r.decision is Outcome.DENY and not r.side_effect_performed


def test_self_approval_and_unauthorized_reviewers_rejected(env):
    aid = pending(env)
    assert env.ag.decide_approval(env.tokens["alice"], aid, True)["reason"] == Reason.APPROVAL_SELF_APPROVAL.value
    assert env.ag.decide_approval(env.tokens["bob"], aid, True)["reason"] == Reason.APPROVAL_UNAUTHORIZED_REVIEWER.value
    assert env.ag.decide_approval(env.tokens["stu"], aid, True)["reason"] == Reason.APPROVAL_UNAUTHORIZED_REVIEWER.value
    assert env.ag.decide_approval(env.tokens["rev"], aid, True)["reason"] == Reason.APPROVAL_UNAUTHORIZED_REVIEWER.value
    assert env.ag.approvals.get(aid)["status"] == "PENDING"


def test_manager_cannot_approve_admin_only_tool(env):
    r = env.ag.submit_tool_call(env.tokens["adm1"], ToolCallRequest("command.run", {"command": "uptime"}, "check uptime", (), uuid.uuid4().hex))
    assert r.decision is Outcome.REQUIRE_APPROVAL
    assert env.ag.decide_approval(env.tokens["mgr1"], r.approval_id, True)["reason"] == Reason.APPROVAL_UNAUTHORIZED_REVIEWER.value
    assert env.ag.decide_approval(env.tokens["adm1"], r.approval_id, True)["reason"] == Reason.APPROVAL_SELF_APPROVAL.value
    assert env.ag.decide_approval(env.tokens["adm2"], r.approval_id, True)["ok"]


def test_expired_approval(env):
    aid = pending(env)
    env.ag.decide_approval(env.tokens["mgr1"], aid, True)
    env.clock.advance(env.ag.settings.approval_ttl_s + 1)
    before = env.state()
    r = env.ag.execute_approved(env.tokens["alice"], aid, req())
    assert Reason.APPROVAL_EXPIRED in r.reasons and env.state() == before
    aid2 = pending_with_new_session(env)
    env.clock.advance(env.ag.settings.approval_ttl_s + 1)
    assert env.ag.decide_approval(env.tokens["mgr1"], aid2, True)["reason"] == Reason.APPROVAL_EXPIRED.value


def pending_with_new_session(env):
    env.tokens["alice"] = env.ag.login("alice", env.pw["alice"])
    env.tokens["mgr1"] = env.ag.login("mgr1", env.pw["mgr1"])
    r = env.ag.submit_tool_call(env.tokens["alice"], req())
    return r.approval_id


def test_other_user_cannot_use_someone_elses_approval(env):
    aid = pending(env)
    env.ag.decide_approval(env.tokens["mgr1"], aid, True)
    r = env.ag.execute_approved(env.tokens["bob"], aid, req())
    assert r.decision is Outcome.DENY and Reason.APPROVAL_WRONG_REQUESTER in r.reasons


def test_direct_database_tampering_of_approval_row_is_detected(env):
    aid = pending(env)
    with env.ag.db.tx() as c:                                    # attacker flips status without the HMAC key
        c.execute("UPDATE approvals SET status='APPROVED', approver_id='x' WHERE approval_id=?", (aid,))
    before = env.state()
    r = env.ag.execute_approved(env.tokens["alice"], aid, req())
    assert Reason.APPROVAL_TAMPERED in r.reasons and env.state() == before


def test_role_downgrade_between_approval_and_execution_blocks_execution(env):
    aid = pending(env)
    env.ag.decide_approval(env.tokens["mgr1"], aid, True)
    env.ag.identity.set_role(env.ids["alice"], "student")
    before = env.state()
    r = env.ag.execute_approved(env.tokens["alice"], aid, req())
    assert r.decision is Outcome.DENY and env.state() == before


def test_policy_version_change_invalidates_approval(env):
    from dataclasses import replace
    aid = pending(env)
    env.ag.decide_approval(env.tokens["mgr1"], aid, True)
    env.ag.policy.bundle = replace(env.ag.policy.bundle, version="policy-2.0.0")
    r = env.ag.execute_approved(env.tokens["alice"], aid, req())
    assert Reason.POLICY_VERSION_CHANGED in r.reasons


def test_approval_is_single_use_under_concurrency(env):
    aid = pending(env)
    env.ag.decide_approval(env.tokens["mgr1"], aid, True)
    results = []
    def go():
        results.append(env.ag.execute_approved(env.tokens["alice"], aid, req()))
    ts = [threading.Thread(target=go) for _ in range(6)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert sum(r.exec_status is ExecStatus.SUCCEEDED for r in results) == 1


def test_unsupported_command_is_rejected_before_it_can_even_be_approved(env):
    before = env.state()
    r = env.ag.submit_tool_call(env.tokens["adm1"], ToolCallRequest("command.run", {"command": "format_disk"}, "", (), uuid.uuid4().hex))
    assert r.decision is Outcome.DENY and Reason.ARGS_INVALID in r.reasons and r.approval_id is None
    assert env.state() == before


def test_audit_unavailable_blocks_side_effects(env):
    aid = pending(env)
    env.ag.decide_approval(env.tokens["mgr1"], aid, True)
    env.ag.audit.fail_for_testing = True
    before = env.state()
    r = env.ag.execute_approved(env.tokens["alice"], aid, req())
    assert r.decision is Outcome.DENY and Reason.EXEC_AUDIT_UNAVAILABLE in r.reasons and env.state() == before
