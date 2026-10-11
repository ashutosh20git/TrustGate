"""Analyst dashboard (blueprint stage 6): escalation queue + live metrics.

    streamlit run services/dashboard/app.py

Reads the audit DB directly and drives escalations through the proxy. Tainted
spans are highlighted; canary cases are mixed into the queue invisibly.
"""

from __future__ import annotations

import os

import httpx
import pandas as pd
import plotly.express as px
import streamlit as st

from trustgate.config import Settings
from trustgate.store import Store

st.set_page_config(page_title="TrustGate", layout="wide")
settings = Settings()
PROXY = os.environ.get("TRUSTGATE_PROXY_URL", settings.proxy_url)


@st.cache_resource
def store() -> Store:
    return Store(settings=settings)


token = st.sidebar.text_input("Your analyst token", type="password")
headers = {"Authorization": f"Bearer {token}"} if token else {}


def proxy_get(path: str):
    try:
        resp = httpx.get(f"{PROXY}{path}", headers=headers, timeout=10)
        if resp.status_code in (401, 503):
            st.warning(resp.json().get("detail", "analyst token required"))
            return None
        return resp.json()
    except httpx.HTTPError as exc:
        st.warning(f"proxy unreachable ({type(exc).__name__}); reading the DB directly")
        return None


st.title("TrustGate v2 — SOC action gate")
metrics = proxy_get("/v1/metrics")
col1, col2, col3, col4, col5 = st.columns(5)
if metrics:
    col1.metric("Decisions", metrics["decisions"])
    col2.metric("Mode", metrics["mode"])
    col3.metric("Fail-closed", metrics["fail_closed"])
    col4.metric("p95 latency (ms)", metrics.get("latency_ms_p95") or 0)
    col5.metric("Audit chain", "ok" if metrics["audit_chain_ok"] else "BROKEN")

tab_queue, tab_actions, tab_analysts, tab_metrics, tab_audit, tab_pins, tab_compliance = st.tabs(
    ["Escalation queue", "Actions & rollback", "Analysts", "Metrics", "Audit", "MCP pins", "Compliance"])

with tab_queue:
    st.subheader("Open escalations")
    second = st.text_input("Second analyst's token (required to approve T2/T3)", type="password")
    items = proxy_get("/v1/escalations?status=open") or []
    if not items:
        st.info("No open escalations.")
    for esc in items:
        with st.expander(f"{esc['tool']}  ·  alert {esc['alert_id']}  ·  {esc.get('recheck_verdict')}"):
            st.write("**Reasons:**")
            for r in esc["reasons"]:
                st.write(f"- {r}")
            if esc.get("tainted_spans"):
                st.error("Tainted spans (the untrusted text that tipped it): " + ", ".join(esc["tainted_spans"]))
            st.json(esc.get("action", {}))
            why = proxy_get(f"/v1/escalations/{esc['id']}/explain") or {}
            for change in why.get("would_allow_if", []):
                st.info(f"Would allow if {change}")
            for block in why.get("never_automatic", []):
                st.warning(f"Never automatic: {block}")
            for note in why.get("notes", []):
                st.caption(note)
            reason = st.text_input("Decision reason", key=f"r-{esc['id']}")
            c1, c2 = st.columns(2)
            if c1.button("Approve", key=f"a-{esc['id']}"):
                resp = httpx.post(f"{PROXY}/v1/escalations/{esc['id']}/approve", json={"reason": reason},
                                  headers={**headers, **({"X-Second-Analyst-Token": second} if second else {})},
                                  timeout=10)
                if resp.status_code >= 400:
                    st.error(resp.json().get("detail", "approval refused"))
                else:
                    st.rerun()
            if c2.button("Reject", key=f"x-{esc['id']}"):
                resp = httpx.post(f"{PROXY}/v1/escalations/{esc['id']}/reject", json={"reason": reason},
                                  headers=headers, timeout=10)
                if resp.status_code >= 400:
                    st.error(resp.json().get("detail", "rejection refused"))
                else:
                    st.rerun()

with tab_metrics:
    if metrics:
        st.subheader("Decisions by tier and outcome")
        rows = [{"key": k, "count": v} for k, v in metrics["by_tier_decision"].items()]
        if rows:
            df = pd.DataFrame(rows)
            st.plotly_chart(px.bar(df, x="key", y="count"), use_container_width=True)
        cols = st.columns(4)
        cols[0].metric("Escalations", sum(metrics["escalations"].values()) if metrics["escalations"] else 0)
        cols[1].metric("Canary caught", metrics["canary_caught"])
        cols[2].metric("Canary missed", metrics["canary_missed"])
        cols[3].metric("Re-check tokens", metrics["recheck_tokens"])
        cols2 = st.columns(4)
        cols2[0].metric("Alerts", metrics["alerts"])
        cols2[1].metric("AI-evasion alerts", metrics["ai_evasion_alerts"])
        cols2[2].metric("Min label coverage", metrics.get("label_coverage_min"))
        cols2[3].metric("Would-block (monitor)", metrics["would_block_monitor"])
        rollout = proxy_get("/v1/rollout")
        if rollout and rollout["tools"]:
            st.subheader("Monitor-mode rollout readiness")
            st.caption(rollout["criteria"])
            st.dataframe(pd.DataFrame(rollout["tools"]))
    st.caption("Full evaluation numbers (ASR@k, gate-only catches): run `python -m eval.run` and load eval/results/summary.json.")
    uploaded = st.file_uploader("Load an eval summary.json", type="json")
    if uploaded:
        import json
        summary = json.load(uploaded)
        head = summary["gate_only_catches"]
        st.metric("Gate-only catches",
                  f"{head['stopped_by_gate']}/{head['passed_detector']} ({head['rate'] * 100:.0f}%)")
        st.dataframe(pd.DataFrame(summary["configs"]).T[["name", "asr@1", "asr@10", "escalation_rate",
                                                         "triage_accuracy", "data_leak_rate"]])

with tab_actions:
    st.subheader("Executed T1/T2 actions")
    st.caption("Each action records its reverse. Security-reducing actions are rolled back automatically "
               "when later evidence shows the alert was manipulated.")
    for act in proxy_get("/v1/actions") or []:
        label = f"{act['tool']}  ·  alert {act['alert_id']}  ·  {act['status']}"
        with st.expander(label):
            st.json({"args": act["args"], "undo": act["undo_tool"], "undo_args": act["undo_args"],
                     "via": act["via"], "reverted_by": act.get("reverted_by"), "reason": act.get("revert_reason")})
            if act["status"] == "executed" and act["undo_tool"]:
                why_revert = st.text_input("Revert reason", key=f"rv-{act['id']}")
                if st.button("Revert", key=f"rb-{act['id']}"):
                    resp = httpx.post(f"{PROXY}/v1/actions/{act['id']}/revert", json={"reason": why_revert},
                                      headers=headers, timeout=10)
                    if resp.status_code >= 400:
                        st.error(resp.json().get("detail", "revert failed"))
                    else:
                        st.rerun()

with tab_analysts:
    scores = proxy_get("/v1/analysts")
    if scores and scores["analysts"]:
        st.caption(scores["criteria"])
        st.dataframe(pd.DataFrame(scores["analysts"]))
    else:
        st.info("No resolved escalations yet.")

with tab_compliance:
    framework = st.selectbox("Framework", ["cert-in", "dpdp", "iso27001"])
    rep = proxy_get(f"/v1/compliance/{framework}")
    if rep:
        st.caption(rep["disclaimer"])
        st.dataframe(pd.DataFrame(rep["controls"])[["id", "requirement", "status", "evidence"]])
        import json as _json
        st.download_button("Download evidence pack (JSON)", _json.dumps(rep, indent=2, default=str),
                           file_name=f"trustgate-{framework}.json", mime="application/json")

with tab_audit:
    alert_id = st.text_input("Filter by alert ID", "")
    data = proxy_get(f"/v1/audit?alert_id={alert_id}" if alert_id else "/v1/audit?limit=200") or []
    if data:
        st.dataframe(pd.DataFrame(data)[["ts", "kind", "alert_id", "tool", "tier", "decision", "mode", "reasons"]])

with tab_pins:
    pins = proxy_get("/v1/mcp/pins") or []
    if pins:
        st.dataframe(pd.DataFrame(pins)[["server", "name", "status", "reasons", "approved_by"]])
    else:
        st.info("No MCP tools pinned yet.")
