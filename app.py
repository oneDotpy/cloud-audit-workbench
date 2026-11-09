"""Cloud Audit Workbench - Streamlit UI.

Run from the project root:  python -m streamlit run app.py
"""
from __future__ import annotations

import json
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from src import report, tracker
from src.mapper import UNMAPPED_DOMAIN, load_mapping
from src.parsers import detect_and_parse
from src.pipeline import DEFAULT_ENVIRONMENT, ROOT, process, run_checkov

PRIORITIES = ["High", "Medium", "Low"]
# Ordinal one-hue ramp (light = Low, dark = High); validated for monotone lightness.
PRIORITY_COLORS = ["#104281", "#2a78d6", "#86b6ef"]
SAMPLES = {"v1 (initial state)": "sample_infra/v1", "v2 (after partial remediation)": "sample_infra/v2"}

st.set_page_config(page_title="Cloud Audit Workbench", layout="wide")
st.markdown(
    "<style>div[data-testid='stMetricValue']{font-size:1.8rem;}"
    " .block-container{padding-top:2rem;}</style>",
    unsafe_allow_html=True,
)


def findings_frame(findings) -> pd.DataFrame:
    rows = [{
        "Status": f.status, "Priority": f.priority, "Control domain": f.control_domain,
        "Issue": f.issue, "Resource": f.resource, "Check ID": f.check_id,
        "Condition": f.condition, "Business risk": f.business_risk,
        "Recommendation": f.recommendation, "File": f.file_path,
        "Lines": f"{f.line_start}-{f.line_end}" if f.line_start else "",
        "Scanner severity": f.raw_severity or "Not provided",
        "Priority rationale": " ".join(f.priority_rationale),
        "Runs open": f.runs_open, "Days open": f.days_open, "Finding ID": f.finding_id,
    } for f in findings]
    df = pd.DataFrame(rows)
    if not df.empty:
        df["Priority"] = pd.Categorical(df["Priority"], PRIORITIES, ordered=True)
        df = df.sort_values(["Priority", "Control domain", "Issue", "Resource"])
    return df


def run_label(r: dict) -> str:
    return f"{r['run_id']}  |  {r.get('environment')}  |  {r.get('target')}"


# ------------------------------------------------------------------ sidebar: inputs
with st.sidebar:
    st.header("New run")
    source = st.radio("Source", ["Scan sample infrastructure", "Upload scanner output"],
                      label_visibility="collapsed")
    if source == "Scan sample infrastructure":
        choice = st.selectbox("Terraform directory", list(SAMPLES))
        st.caption("Runs Checkov locally against the Terraform files. No cloud account is accessed.")
        if st.button("Run Checkov scan", type="primary", width="stretch"):
            with st.spinner("Running Checkov..."):
                run, _, _ = process(run_checkov(ROOT / SAMPLES[choice]), SAMPLES[choice], DEFAULT_ENVIRONMENT)
            st.session_state["selected_run"] = run["run_id"]
            st.success(f"Saved run {run['run_id']}")
    else:
        upload = st.file_uploader("Checkov or Prowler JSON", type=["json"])
        env = st.text_input("Environment name", value="uploaded-environment",
                            help="Runs with the same environment name are compared with each other.")
        if upload and st.button("Import file", type="primary", width="stretch"):
            try:
                data = json.loads(upload.getvalue())
                tool, _, _ = detect_and_parse(data)
                run, _, _ = process(data, upload.name, env)
                st.session_state["selected_run"] = run["run_id"]
                st.success(f"Imported {tool} results as run {run['run_id']}")
            except (ValueError, json.JSONDecodeError) as exc:
                st.error(f"Could not read file: {exc}")

    st.divider()
    st.caption("Sample infrastructure is synthetic and intentionally insecure. "
               "This tool never connects to or modifies real cloud resources.")

# ------------------------------------------------------------------ select run
st.title("Cloud Audit Workbench")
st.caption("Scanner findings normalized, mapped to IT control domains, prioritized and tracked across runs.")

runs = tracker.list_runs()
if not runs:
    st.info("No runs yet. Use the sidebar to scan the sample infrastructure or upload scanner output.")
    st.stop()

by_id = {r["run_id"]: r for r in runs}
ordered_ids = [r["run_id"] for r in reversed(runs)]
default_id = st.session_state.get("selected_run", ordered_ids[0])
current_id = st.selectbox("Run", ordered_ids, index=ordered_ids.index(default_id) if default_id in ordered_ids else 0,
                          format_func=lambda i: run_label(by_id[i]))
current = by_id[current_id]
previous = tracker.previous_run(current, runs)
comparison = tracker.compare(previous, current, runs)
findings = comparison.current_findings
df = findings_frame(findings)

# ------------------------------------------------------------------ metrics
m = st.columns(7)
m[0].metric("Findings in scope", len(findings))
for i, p in enumerate(PRIORITIES, start=1):
    m[i].metric(f"{p} priority", sum(f.priority == p for f in findings))
m[4].metric("Unmapped", sum(not f.is_mapped for f in findings), help=UNMAPPED_DOMAIN)
if previous:
    m[5].metric("New", comparison.counts["New"], help="New since the previous run")
    m[6].metric("Resolved", comparison.counts["Resolved"], help="Resolved since the previous run")
else:
    m[5].metric("New", "n/a")
    m[6].metric("Resolved", "n/a")

meta = current.get("scan_summary", {})
st.caption(f"Scope: {current.get('target')}  |  {current.get('tool')} {current.get('tool_version') or ''}  |  "
           f"run date {current['timestamp']}  |  checks passed {meta.get('passed', 0)}, failed {meta.get('failed', 0)}  |  "
           + (f"compared with {previous['run_id']}" if previous else "no previous run in this environment"))

xlsx_bytes = report.build_workbook(current, comparison, previous)
md_text = report.build_markdown(current, comparison, previous)
d1, d2, _ = st.columns([1.3, 1.3, 3])
d1.download_button("Download Excel workpaper", xlsx_bytes, file_name=f"workpaper_{current_id}.xlsx",
                   mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                   type="primary", width="stretch")
d2.download_button("Download observations (.md)", md_text, file_name=f"observations_{current_id}.md",
                   mime="text/markdown", width="stretch")

tab_overview, tab_findings, tab_compare, tab_obs = st.tabs(
    ["Overview", "Findings", "Run comparison", "Observations"])

# ------------------------------------------------------------------ overview
with tab_overview:
    domains, _ = load_mapping()
    domain_order = domains + [UNMAPPED_DOMAIN]
    counts = (df.groupby(["Control domain", "Priority"], observed=False).size().reset_index(name="Findings")
              if not df.empty else pd.DataFrame(columns=["Control domain", "Priority", "Findings"]))
    counts = counts[counts["Findings"] > 0]
    st.subheader("Findings by control domain")
    chart = (
        alt.Chart(counts)
        .mark_bar(cornerRadiusEnd=4, stroke="white", strokeWidth=2, size=22)
        .encode(
            y=alt.Y("Control domain:N", sort=domain_order, title=None, axis=alt.Axis(labelLimit=260)),
            x=alt.X("sum(Findings):Q", title="Findings", axis=alt.Axis(grid=True, tickMinStep=1)),
            color=alt.Color("Priority:N", scale=alt.Scale(domain=PRIORITIES, range=PRIORITY_COLORS),
                            legend=alt.Legend(orient="top", title=None)),
            order=alt.Order("priority_rank:Q"),
            tooltip=["Control domain", "Priority", "Findings"],
        )
        .transform_calculate(priority_rank="indexof(['High','Medium','Low'], datum.Priority)")
        .properties(height=alt.Step(36))
        .configure_axis(gridColor="#e6e6e3", domainColor="#bfbfbb", labelColor="#3d3d3a", titleColor="#6b6b67")
        .configure_view(strokeWidth=0)
    )
    st.altair_chart(chart, width="stretch")

    pivot = (df.pivot_table(index="Control domain", columns="Priority", values="Finding ID",
                            aggfunc="count", fill_value=0, observed=False)
             .reindex(domain_order, fill_value=0))
    pivot["Total"] = pivot.sum(axis=1)
    st.dataframe(pivot, width="stretch")

# ------------------------------------------------------------------ findings
with tab_findings:
    f1, f2, f3, f4 = st.columns([2, 1.2, 1.2, 2])
    sel_domains = f1.multiselect("Control domain", domain_order)
    sel_prio = f2.multiselect("Priority", PRIORITIES)
    sel_status = f3.multiselect("Status", ["New", "Persisting"])
    search = f4.text_input("Search resource, check or issue")
    view = df.copy()
    if sel_domains:
        view = view[view["Control domain"].isin(sel_domains)]
    if sel_prio:
        view = view[view["Priority"].isin(sel_prio)]
    if sel_status:
        view = view[view["Status"].isin(sel_status)]
    if search:
        s = search.lower()
        view = view[view[["Resource", "Check ID", "Issue"]].apply(
            lambda r: s in " ".join(map(str, r)).lower(), axis=1)]
    st.caption(f"{len(view)} of {len(df)} findings")
    st.dataframe(view, width="stretch", hide_index=True, height=520,
                 column_config={"Condition": st.column_config.TextColumn(width="large"),
                                "Business risk": st.column_config.TextColumn(width="large")})

# ------------------------------------------------------------------ comparison
with tab_compare:
    st.subheader("Compare two runs")
    c1, c2 = st.columns(2)
    older_default = previous["run_id"] if previous else ordered_ids[-1]
    a_id = c1.selectbox("Earlier run", ordered_ids, index=ordered_ids.index(older_default),
                        format_func=lambda i: run_label(by_id[i]), key="cmp_a")
    b_id = c2.selectbox("Later run", ordered_ids, index=ordered_ids.index(current_id),
                        format_func=lambda i: run_label(by_id[i]), key="cmp_b")
    if a_id == b_id:
        st.warning("Select two different runs.")
    else:
        a, b = sorted([by_id[a_id], by_id[b_id]], key=lambda r: (r["timestamp"], r["run_id"]))
        if a.get("environment") != b.get("environment"):
            st.warning("These runs belong to different environments; most findings will appear as New or Resolved.")
        cmp = tracker.compare(a, b, runs)
        k = st.columns(3)
        k[0].metric("New", cmp.counts["New"])
        k[1].metric("Resolved", cmp.counts["Resolved"])
        k[2].metric("Persisting", cmp.counts["Persisting"])
        cols = ["Status", "Priority", "Control domain", "Issue", "Resource", "Check ID", "Runs open", "Days open"]
        for label, items in (("New", cmp.new), ("Resolved", cmp.resolved), ("Persisting", cmp.persisting)):
            st.markdown(f"**{label}** ({len(items)})")
            if items:
                st.dataframe(findings_frame(items)[cols], width="stretch", hide_index=True)
            else:
                st.caption("None.")

# ------------------------------------------------------------------ observations
with tab_obs:
    st.markdown(md_text)
