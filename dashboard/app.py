"""Streamlit dashboard. SIMULATION MODE: all tools act on a synthetic sandbox.
This UI enforces NOTHING: it holds only a session token and calls AgentGuard's authorised APIs.
Hiding a widget is cosmetic; the backend re-checks every action."""
from __future__ import annotations

import json
import time
import uuid

import streamlit as st

from agentguard.agent.planner import KeywordPlanner
from agentguard.api import AgentGuard
from agentguard.common import ContentItem, ToolCallRequest
from agentguard.config import Settings
from agentguard.errors import AuthError

st.set_page_config(page_title="AgentGuard", layout="wide")


@st.cache_resource
def get_ag() -> AgentGuard:
    return AgentGuard(Settings.from_env())


ag = get_ag()
st.warning("SIMULATION MODE: synthetic data, simulated email/records, and `command.run` never executes anything on the host.")

if "token" not in st.session_state:
    st.title("AgentGuard sign-in")
    with st.form("login"):
        u, p = st.text_input("Username"), st.text_input("Password", type="password")
        if st.form_submit_button("Sign in"):
            try:
                st.session_state.token = ag.login(u, p)
                st.rerun()
            except AuthError as e:
                st.error(f"Sign-in failed ({e.reason.value})")
    st.caption("Demo accounts are created by `python scripts/seed_demo.py`; roles are fixed on the server.")
    st.stop()

tok = st.session_state.token
try:
    me = ag.whoami(tok)
except AuthError:
    del st.session_state["token"]; st.rerun()
st.sidebar.write(f"**{me.display_name}** · role: `{me.role}` (server-side)")
if st.sidebar.button("Sign out"):
    ag.logout(tok); del st.session_state["token"]; st.rerun()
pages = ["Agent console", "Trust", "Approvals"] + (["Audit & incidents", "Review & feedback", "Models & evaluation"] if me.role in ("reviewer", "admin") else [])
page = st.sidebar.radio("Page", pages)


def show_result(r):
    c1, c2, c3 = st.columns(3)
    c1.metric("Decision", r.decision.value); c2.metric("Risk score", "-" if r.risk_score is None else f"{r.risk_score:.0f}")
    c3.metric("Trust score", "-" if r.trust_score is None else f"{r.trust_score:.2f}")
    st.write("**Reason codes:**", ", ".join(x.value for x in r.reasons) or "-", "· **Class:**", r.outcome_class.value, "· **Exec:**", r.exec_status.value)
    if r.factors:
        with st.expander("Why this risk score (explainable factors)"):
            st.table([{"factor": f["name"], "points": f["points"], "detail": f["detail"]} for f in r.factors])
    if r.signals:
        with st.expander("Detector signals"):
            st.table([{k: s[k] for k in ("name", "severity", "source", "detector", "excerpt")} for s in r.signals])
    if r.output:
        st.caption("Tool output is UNTRUSTED data:"); st.code(r.output)
    if r.approval_id:
        st.info(f"Approval required. approval_id = {r.approval_id}")


if page == "Agent console":
    st.header("Agent console")
    text = st.text_area("Request", "What's the weather in Tokyo?")
    with st.expander("Optional: simulate a retrieved (untrusted) document the agent read"):
        doc = st.text_area("Untrusted content", "")
    calls = KeywordPlanner().plan(text)
    st.caption("The planner only *proposes* calls. Each proposal is authorised independently by the gateway.")
    if not calls:
        st.info("No tool matched this request.")
    for i, pc in enumerate(calls):
        with st.container(border=True):
            st.write(f"Proposed: `{pc.tool}` {json.dumps(pc.arguments)}")
            args = st.text_input("Arguments (JSON)", json.dumps(pc.arguments), key=f"a{i}")
            if st.button("Submit to gateway", key=f"b{i}"):
                try:
                    a = json.loads(args)
                    r = ag.submit_tool_call(tok, ToolCallRequest(pc.tool, a, text, (ContentItem("doc", doc),) if doc else (), uuid.uuid4().hex))
                    show_result(r)
                except json.JSONDecodeError:
                    st.error("Arguments must be valid JSON")
    st.subheader("Execute an approved request")
    aid = st.text_input("approval_id"); tool = st.text_input("tool"); aj = st.text_input("arguments (JSON, must match exactly)")
    if st.button("Execute approved") and aid:
        try:
            show_result(ag.execute_approved(tok, aid, ToolCallRequest(tool, json.loads(aj or "{}"), "", (), uuid.uuid4().hex)))
        except json.JSONDecodeError:
            st.error("Invalid JSON")

elif page == "Trust":
    st.header("Trust state")
    uid = me.user_id
    if me.role in ("reviewer", "admin"):
        users = ag.list_users(tok); pick = st.selectbox("User", users, format_func=lambda u: f"{u['username']} ({u['role']})"); uid = pick["user_id"]
    v = ag.trust_view(tok, uid); s = v["snapshot"]
    st.metric("Trust estimate", f"{s.score:.2f}", s.level); st.caption(f"data quality: {s.data_quality}. An estimate used to raise scrutiny; never a verdict and never a permission.")
    st.write(s.explain()); st.dataframe(v["history"])

elif page == "Approvals":
    st.header("Pending approvals")
    try:
        rows = ag.pending_approvals(tok)
        for r in rows:
            with st.container(border=True):
                st.write(f"`{r['tool']}` on `{r['resource']}` requested by `{r['requester_id'][:8]}…` · flags: {r['risk_flags']}")
                c1, c2 = st.columns(2)
                if c1.button("Approve", key="ap" + r["approval_id"]):
                    st.write(ag.decide_approval(tok, r["approval_id"], True))
                if c2.button("Reject", key="rj" + r["approval_id"]):
                    st.write(ag.decide_approval(tok, r["approval_id"], False))
        if not rows:
            st.info("Nothing pending.")
    except AuthError:
        st.error("Your role cannot review approvals (enforced by the backend).")

elif page == "Audit & incidents":
    st.header("Audit & incidents")
    ok, bad = ag.audit_verify(tok)
    (st.success if ok else st.error)("Audit chain intact" if ok else f"AUDIT CHAIN BROKEN at seq {bad}")
    c = st.columns(4)
    et = c[0].text_input("event_type"); oc = c[1].selectbox("outcome", ["", "ALLOW", "DENY", "REQUIRE_APPROVAL"]); tl = c[2].text_input("tool"); hrs = c[3].number_input("last N hours (0 = all)", 0, 10000, 0)
    ev = ag.audit_search(tok, event_type=et or None, outcome=oc or None, tool=tl or None, since=(time.time() - hrs * 3600) if hrs else None, limit=500)
    st.dataframe([{k: e.get(k) for k in ("ts", "event_type", "principal_id", "tool", "outcome", "outcome_class", "reason_codes", "request_id", "exec_status")} for e in ev])
    st.subheader("Alerts (computed from the log)")
    inj = [e for e in ev if e.get("outcome_class") == "SUSPECTED_MALICIOUS"]
    if inj: st.warning(f"{len(inj)} suspected-malicious events in this view (unverified; review before acting).")
    if any("RISK_ML_UNAVAILABLE" in e.get("reason_codes", []) for e in ev): st.warning("ML advisor was unavailable for some requests; protected calls were escalated.")
    if any("POLICY_UNAVAILABLE" in e.get("reason_codes", []) for e in ev): st.error("Policy service outage observed; requests failed closed.")
    st.subheader("Incident investigation")
    rid = st.text_input("request_id"); 
    if rid: st.json(ag.audit_search(tok, request_id=rid, limit=50))
    st.bar_chart({k: sum(1 for e in ev if e.get("outcome") == k) for k in ("ALLOW", "DENY", "REQUIRE_APPROVAL")})

elif page == "Review & feedback":
    st.header("False-positive review and verified labels")
    for t in [x for x in ag.recent_trust_events(tok, 50) if x["event_type"] in ("INJECTION_SUSPECTED", "PATH_VIOLATION", "SECRET_REQUEST")]:
        with st.container(border=True):
            st.write(f"`{t['event_type']}` severity {t['severity']:.2f} · user `{t['user_id'][:8]}…` · request `{t['request_id']}`")
            ev = st.text_input("Evidence (required)", key="e" + t["event_id"])
            c1, c2 = st.columns(2)
            if c1.button("False positive", key="fp" + t["event_id"]) and ev: st.write(ag.review_trust_event(tok, t["event_id"], "false_positive", ev))
            if c2.button("Confirmed malicious", key="cm" + t["event_id"]) and ev: st.write(ag.review_trust_event(tok, t["event_id"], "confirmed_malicious", ev))
    st.caption("Model predictions can never become labels; labels require a human reviewer and evidence.")

elif page == "Models & evaluation":
    st.header("Models & evaluation")
    for m in ag.models_overview(tok):
        with st.container(border=True):
            st.write(f"**{m['version']}** · {m['status']} · sha256 `{m['sha256'][:12]}…`")
            if m["report"]:
                for suite in ("held_out_test_family_split", "adversarial_eval"):
                    st.write(suite); st.json({k: {x: v for x, v in m["report"][suite][k].items() if x in ("precision", "recall", "fpr", "pr_auc", "confusion_matrix", "ci95", "n")} for k in ("ml", "regex_baseline")})
            c = st.columns(3)
            if c[0].button("Run gate", key="g" + m["version"]): st.write(ag.model_gate(tok, m["version"]))
            if c[1].button("Approve + activate", key="a" + m["version"]):
                try: ag.model_approve_and_activate(tok, m["version"]); st.success("activated")
                except Exception as e: st.error(str(e))
            if c[2].button("Rollback", key="r" + m["version"]):
                try: st.success(ag.model_rollback(tok))
                except Exception as e: st.error(str(e))
    st.caption("Runtime never retrains. Models change only through this gated, audited workflow.")
