import os, sqlite3, datetime
import pandas as pd
import plotly.express as px
import streamlit as st
from src.journey import explain, timeline, proof_card, counterfactual

st.set_page_config(page_title="INSIGHT-360", layout="wide")
DB = "feedback.db"
PASSWORD = os.environ.get("INSIGHT_PASS", "insight360")   # maathikonga
STATUS = {"Under Investigation": "Investigating", "Approved Work": "Approved",
          "False Positive": "False Alert", "Confirmed Threat": "Confirmed", "Close case": "Closed"}


def db():
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS cases (key TEXT PRIMARY KEY, status TEXT, note TEXT, updated TEXT, expires TEXT)")
    con.execute("CREATE TABLE IF NOT EXISTS audit (ts TEXT, actor TEXT, key TEXT, action TEXT)")
    return con


def audit(key, action):
    con = db()
    con.execute("INSERT INTO audit VALUES (?,?,?,?)", (datetime.datetime.now().isoformat(), "admin", key, action))
    con.commit(); con.close()


def set_case(key, label, note):
    status = STATUS[label]
    now = datetime.datetime.now()
    # Approved / False Alert = 14 naal temporary exception (auto-expire). Baseline-ai maathaadhu.
    exp = (now + datetime.timedelta(days=14)).isoformat() if status in ("Approved", "False Alert") else ""
    con = db()
    con.execute("INSERT OR REPLACE INTO cases VALUES (?,?,?,?,?)", (key, status, note, now.isoformat(), exp))
    con.commit(); con.close()
    audit(key, f"{label} -> {status}; note: {note}")


# ---- login ----
if not st.session_state.get("ok"):
    st.title("INSIGHT-360 login")
    pw = st.text_input("Admin password", type="password")
    if st.button("Login"):
        if pw == PASSWORD:
            st.session_state["ok"] = True
            audit("-", "login")
            st.rerun()
        else:
            st.error("Wrong password")
    st.stop()


@st.cache_data
def load():
    return (pd.read_parquet("data/processed/scored.parquet"),
            pd.read_parquet("data/processed/incidents.parquet"),
            pd.read_csv("data/processed/insiders_hashed.csv"))


d, inc, ins = load()
con = db()
cases = pd.read_sql("SELECT * FROM cases", con)
aud = pd.read_sql("SELECT * FROM audit ORDER BY ts DESC", con)
con.close()

inc["key"] = inc["user"] + "|" + inc["start"].dt.strftime("%Y-%m-%d")
inc = inc.merge(cases[["key", "status"]], on="key", how="left")
inc["status"] = inc["status"].fillna("New")

now_iso = datetime.datetime.now().isoformat()
active_exc = set(cases[(cases["status"].isin(["Approved", "False Alert"])) & (cases["expires"] > now_iso)]["key"])
inc["adj_risk"] = inc.apply(lambda r: round(r["peak_risk"] * 0.8, 1) if r["key"] in active_exc else r["peak_risk"], axis=1)

st.title("INSIGHT-360")
st.caption("Explainable, privacy-aware insider-threat early warning. Decision-support only: a high score means human review is needed, not guilt.")

st.sidebar.header("Filters")
min_risk = st.sidebar.slider("Minimum peak risk", 0, 100, 30)
status_f = st.sidebar.multiselect("Case status", ["New", "Investigating", "Approved", "False Alert", "Confirmed", "Closed"],
                                  default=["New", "Investigating", "Confirmed"])
st.sidebar.info("Privacy mode: hashed user IDs, metadata and counts only. No email or file content is used.")

view = inc[(inc["adj_risk"] >= min_risk) & (inc["status"].isin(status_f))].sort_values("adj_risk", ascending=False)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Users monitored", d["user"].nunique())
c2.metric("Open incidents", len(view))
c3.metric("Alert days grouped", int(view["alert_days"].sum()) if len(view) else 0)
c4.metric("Cases actioned", len(cases))

st.subheader("Incident ranking")
show = ["incident_id", "user", "start", "end", "alert_days", "peak_risk", "adj_risk", "level", "trust", "trust_level", "chain", "status"]
st.dataframe(view[show], width="stretch", height=250)
st.download_button("Download incident report (CSV)", view[show].to_csv(index=False), "incident_report.csv")

with st.expander("Model evaluation: Rules vs Isolation Forest vs Hybrid"):
    try:
        st.dataframe(pd.read_csv("data/processed/evaluation.csv"), width="stretch")
        st.caption("Labels: CERT answer key. Attack-window days are positives. Ovvoru model-um top 1% user-days mattum alert.")
    except FileNotFoundError:
        st.write("Run src/evaluate.py first.")

if view.empty:
    st.stop()

sel = st.selectbox("Select incident", view["incident_id"] + " | " + view["user"] + " | " + view["level"])
row_inc = view[view["incident_id"] == sel.split(" | ")[0]].iloc[0]
user, key = row_inc["user"], row_inc["key"]
peak = d[(d["user"] == user) & (d["day"] == row_inc["peak_day"])].iloc[0]
e = explain(peak)

st.subheader(f"{row_inc['incident_id']}  |  User {user}  |  Status: {row_inc['status']}")
a, b, c, dd = st.columns(4)
a.metric("Threat Risk Score", f"{e['risk']} / 100", e["level"])
b.metric("Alert Trust Score", f"{e['trust']} / 100", e["trust_level"])
c.metric("Journey stage", e["stage"])
dd.metric("Risk chain", e["chain"])
st.write(f"**Predicted next stage:** {e['next_stage']}   |   **Peak day:** {e['day'].date()}")
if e["trust_level"] == "Low":
    st.warning("Low trust: behaviour looks risky but history or evidence is limited. Human verification needed before any action.")

left, right = st.columns(2)
with left:
    st.markdown("**What changed? (behavioural proof)**")
    st.dataframe(proof_card(peak), width="stretch", hide_index=True)
    st.markdown("**Why this alert**")
    for r in e["reasons"] or ["No single strong signal. Risk comes from combined small deviations."]:
        st.write("- " + r)
    st.markdown("**Least-disruptive response**")
    st.info(e["action"])
with right:
    fig = px.line(d[d["user"] == user].sort_values("day"), x="day", y="risk", title="Risk timeline")
    fig.add_hline(y=55, line_dash="dash", annotation_text="Suspicious")
    fig.add_hline(y=75, line_dash="dash", annotation_text="High")
    st.plotly_chart(fig, width="stretch")
    st.markdown("**Counterfactual: which signal drove the risk?**")
    st.dataframe(counterfactual(peak), width="stretch", hide_index=True)
    if bool(peak["override"]):
        st.caption("Critical override active: score floor 90 applied because file-copy spike + transfer occurred together.")

st.markdown("**Behaviour journey (14 active days till incident end)**")
st.dataframe(timeline(d, user, upto=row_inc["end"]), width="stretch", hide_index=True)

st.markdown("**Case management**")
note = st.text_input("Analyst note", key="note")
cols = st.columns(5)
for col, label in zip(cols, STATUS):
    if col.button(label):
        set_case(key, label, note)
        st.success(f"Saved: {label}. Refresh pannina status update aagum.")
st.caption("Approved / False Positive = 14-day temporary exception (auto-expires, risk x0.8). Baseline-ai feedback maathaadhu. Ella actions-um audit log la save aagum.")

with st.expander("Audit log"):
    st.dataframe(aud, width="stretch")

with st.expander("Ground truth (evaluation only, not shown to real admins)"):
    r = ins[ins["user"] == user]
    st.write("Not a labelled insider in CERT r4.2." if r.empty else r[["scenario", "start", "end"]].to_string(index=False))