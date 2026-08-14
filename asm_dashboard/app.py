from __future__ import annotations

import datetime
import os
import sys
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import plotly.express as px
import streamlit as st

from asm_dashboard import auth, db, metrics
from assess_attack_surface import load_dotenv


PAGE_SIZE = 200
KPI_LABELS = [
    ("Active Findings", "active_findings"),
    ("Active High", "active_high"),
    ("New Latest Scan", "new_latest_scan"),
    ("Resolved This Quarter", "resolved_this_quarter"),
    ("Sensitive Exposure 80/443", "sensitive_exposure_80_443"),
    ("Current Non-standard Ports", "current_non_standard_ports"),
]


def require_login() -> bool:
    load_dotenv()
    if not auth.password_configured():
        st.error("DASHBOARD_PASSWORD is not configured. Dashboard access is disabled.")
        return False
    if st.session_state.get("authenticated"):
        return True
    with st.form("login_form"):
        password = st.text_input("Dashboard password", type="password")
        submitted = st.form_submit_button("Sign in")
    if submitted and auth.password_matches(password):
        st.session_state["authenticated"] = True
        st.rerun()
    if submitted:
        st.error("Invalid password.")
    return False


def get_connection():
    load_dotenv()
    if not db.configured():
        st.error("RDS configuration is incomplete. Set RDS_HOST, RDS_DB, RDS_USER, and RDS_PASSWORD.")
        st.stop()
    return db.connect()


def sidebar_page() -> str:
    st.sidebar.title("ASM Dashboard")
    return st.sidebar.radio("Navigation", ["Current Status", "Historical Results", "Whitelist Rules"])


def filter_state(options: dict[str, list[Any]], key_prefix: str = "current") -> db.FilterState:
    with st.expander("Filters", expanded=True):
        col1, col2, col3 = st.columns(3)
        with col1:
            risk_levels = st.multiselect("Risk Level", options.get("risk_levels", []), key=f"{key_prefix}_risk")
            ports = st.multiselect("Port", options.get("ports", []), key=f"{key_prefix}_port")
        with col2:
            cloud_platforms = st.multiselect(
                "Cloud Platform", options.get("cloud_platforms", []), key=f"{key_prefix}_platform"
            )
            cloud_accounts = st.multiselect(
                "Cloud Account Name", options.get("cloud_accounts", []), key=f"{key_prefix}_account"
            )
        with col3:
            check_ids = st.multiselect("Check ID", options.get("check_ids", []), key=f"{key_prefix}_check")
            exposure_levels = st.multiselect(
                "Exposure Level", options.get("exposure_levels", []), key=f"{key_prefix}_exposure"
            )
        search = st.text_input("Endpoint or host search", key=f"{key_prefix}_search")
        date_range = st.date_input("First Seen date range", value=(), key=f"{key_prefix}_first_seen")
    first_seen_start = date_range[0] if isinstance(date_range, tuple) and len(date_range) >= 1 else None
    first_seen_end = date_range[1] if isinstance(date_range, tuple) and len(date_range) >= 2 else None
    return db.FilterState(
        risk_levels=list(risk_levels),
        ports=list(ports),
        cloud_platforms=list(cloud_platforms),
        cloud_accounts=list(cloud_accounts),
        check_ids=list(check_ids),
        exposure_levels=list(exposure_levels),
        search=search,
        first_seen_start=first_seen_start,
        first_seen_end=first_seen_end,
    )


def render_kpis(kpis: dict[str, int]) -> None:
    cols = st.columns(3)
    for index, (label, key) in enumerate(KPI_LABELS):
        cols[index % 3].metric(label, kpis.get(key, 0))


def render_current_charts(current_rows: list[dict[str, Any]], trend_rows: list[dict[str, Any]]) -> None:
    trend = metrics.trend_frame(trend_rows)
    left, right = st.columns([2, 1])
    with left:
        st.subheader("Exposure trend")
        if trend.empty:
            st.info("No trend data available.")
        else:
            figure = px.line(trend, x="date", y="count", color="metric", markers=True)
            figure.update_xaxes(dtick="D1", tickformat="%Y-%m-%d")
            st.plotly_chart(figure, use_container_width=True)
    with right:
        st.subheader("Risk distribution")
        risk = metrics.distribution(current_rows, "risk_level")
        if risk.empty:
            st.info("No risk distribution data.")
        else:
            st.plotly_chart(px.pie(risk, names="risk_level", values="count"), use_container_width=True)
    col1, col2, col3 = st.columns(3)
    for column, title, key in [
        (col1, "Cloud Accounts", "cloud_account_name"),
        (col2, "Cloud Platforms", "cloud_platform"),
        (col3, "Top Check IDs", "check_id"),
    ]:
        with column:
            st.subheader(title)
            frame = metrics.distribution(current_rows, key)
            if frame.empty:
                st.info("No data.")
            else:
                st.plotly_chart(px.bar(frame, x=key, y="count"), use_container_width=True)


def table_records(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records = []
    for row in rows:
        endpoint = str(row.get("endpoint_name") or "").strip()
        endpoint_url = endpoint if endpoint.startswith(("http://", "https://")) else ""
        wiz_url = str(row.get("wiz_link") or "").strip()
        records.append(
            {
                "Expand": "View",
                "Endpoint Name": endpoint,
                "Endpoint URL": endpoint_url,
                "Port": row.get("port"),
                "Cloud Platform": row.get("cloud_platform"),
                "Cloud Account Name": row.get("cloud_account_name"),
                "Risk Level": row.get("risk_level"),
                "Evidence": row.get("evidence"),
                "First Seen At": row.get("first_seen_at"),
                "Wiz Link": wiz_url,
                "Check ID": row.get("check_id"),
                "Exposure Level": row.get("exposure_level"),
                "_row": row,
            }
        )
    return records


def table_frame(rows: list[dict[str, Any]]) -> pd.DataFrame:
    records = table_records(rows)
    return pd.DataFrame(records)


def render_page_controls(total: int, key: str) -> int:
    page_count = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    return int(st.number_input("Page", min_value=1, max_value=page_count, value=1, step=1, key=key))


def selected_row_indices(selection: Any) -> list[int]:
    if isinstance(selection, dict):
        return list(selection.get("selection", {}).get("rows", []))
    selection_obj = getattr(selection, "selection", None)
    if selection_obj is None:
        return []
    rows = getattr(selection_obj, "rows", [])
    return list(rows)


def open_whitelist_dialog(connection, row: dict[str, Any], dialog_key: str) -> None:
    @st.dialog("Add to whitelist")
    def whitelist_dialog() -> None:
        st.write(f"Endpoint: `{row.get('endpoint_name')}`")
        st.write(f"Port: `{row.get('port')}`")
        with st.form(dialog_key):
            reason = st.text_area("Reason")
            operator_name = st.text_input("Operator Name")
            submitted = st.form_submit_button("Confirm whitelist")
        if submitted:
            try:
                db.create_whitelist_rule(
                    connection,
                    endpoint_name=str(row.get("endpoint_name") or ""),
                    port=row.get("port"),
                    reason=reason,
                    operator_name=operator_name,
                )
            except Exception as exc:
                st.error(f"Whitelist failed: {type(exc).__name__}: {exc}")
            else:
                st.success("Whitelist rule created and matching current/history findings updated.")
                st.rerun()

    whitelist_dialog()


def render_finding_table(connection, result: db.PageResult, page_key: str, allow_whitelist: bool) -> None:
    st.caption(f"{result.total} findings, showing page {result.page} with up to {result.page_size} rows.")
    if not result.rows:
        st.info("No findings match the filters.")
        return
    frame = table_frame(result.rows)
    visible = frame.drop(columns=["_row"])
    selection = st.dataframe(
        visible,
        use_container_width=True,
        hide_index=True,
        selection_mode="single-row",
        on_select="rerun",
        column_config={
            "Expand": st.column_config.TextColumn("Expand", help="Select a row to expand details below."),
            "Endpoint Name": st.column_config.LinkColumn("Endpoint Name"),
            "Endpoint URL": None,
            "Wiz Link": st.column_config.LinkColumn("Wiz Link", display_text="Wiz Link"),
        },
    )
    selected_rows = selected_row_indices(selection)
    if not selected_rows:
        st.info("Select a row to expand details.")
        return
    selected = frame.iloc[selected_rows[0]]["_row"]
    st.subheader("Finding details")
    st.json(selected, expanded=False)
    if allow_whitelist and st.button("Whitelist", key=f"open_whitelist_{page_key}_{selected_rows[0]}"):
        open_whitelist_dialog(connection, selected, f"whitelist_{page_key}_{selected_rows[0]}")


def current_page_value(key: str) -> int:
    return max(1, int(st.session_state.get(key, 1)))


def render_current_table(connection, filters: db.FilterState) -> None:
    page = current_page_value("current_page")
    result = db.fetch_current_findings(connection, filters, page=page, page_size=PAGE_SIZE)
    render_finding_table(connection, result, "current_page", allow_whitelist=True)
    render_page_controls(result.total, "current_page")


def current_status_page(connection) -> None:
    st.title("ASM Current Status")
    st.caption("Executive view of active, non-whitelisted attack surface findings.")
    latest = db.fetch_latest_scan(connection)
    latest_scan_id = latest.get("scan_id") if latest else None
    current_rows = db.fetch_current_kpi_rows(connection)
    quarter_start = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=90)
    resolved_this_quarter = db.fetch_resolved_high_count_since(connection, quarter_start)
    kpis = metrics.current_kpis(
        current_rows,
        latest_scan_id=latest_scan_id,
        resolved_this_quarter=resolved_this_quarter,
    )
    render_kpis(kpis)
    render_current_charts(current_rows, db.fetch_trend_rows(connection))
    options = db.fetch_filter_options(connection, current_only=True)
    filters = filter_state(options, key_prefix="current")
    render_current_table(connection, filters)


def historical_results_page(connection) -> None:
    st.title("Historical Results")
    st.caption("Scan-history view by asm_scans.started_at date. Includes whitelisted findings.")
    selected_date = st.date_input("Scan date", value=datetime.date.today(), key="history_date")
    options = db.fetch_filter_options(connection, current_only=False)
    filters = filter_state(options, key_prefix="history")
    page = current_page_value("history_page")
    result = db.fetch_historical_findings(connection, selected_date, filters, page=page, page_size=PAGE_SIZE)
    rows = result.rows
    high_count = sum(1 for row in rows if str(row.get("risk_level") or "").lower() == "high")
    whitelisted_count = sum(1 for row in rows if bool(row.get("whitelisted")))
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Scans on date", len({row.get("scan_id") for row in rows if row.get("scan_id")}))
    col2.metric("Total findings", result.total)
    col3.metric("High findings on page", high_count)
    col4.metric("Whitelisted on page", whitelisted_count)
    render_finding_table(connection, result, "history_page", allow_whitelist=False)
    render_page_controls(result.total, "history_page")


def whitelist_rules_page(connection) -> None:
    st.title("Whitelist Rules")
    st.caption("Dashboard-managed endpoint_name + port whitelist rules.")
    rules = db.fetch_whitelist_rules(connection)
    if not rules:
        st.info("No whitelist rules have been created.")
        return
    frame = pd.DataFrame(rules)
    selection = st.dataframe(
        frame,
        use_container_width=True,
        hide_index=True,
        selection_mode="single-row",
        on_select="rerun",
    )
    selected_rows = selected_row_indices(selection)
    if not selected_rows:
        return
    selected = rules[selected_rows[0]]
    st.subheader("Rule details")
    st.json(selected, expanded=False)
    if not selected.get("active"):
        st.info("This rule is already inactive.")
        return
    with st.form("deactivate_rule"):
        operator_name = st.text_input("Operator name")
        reason = st.text_area("Deactivation reason")
        submitted = st.form_submit_button("Deactivate rule")
    if submitted:
        try:
            db.deactivate_whitelist_rule(
                connection,
                rule_id=int(selected["id"]),
                operator_name=operator_name,
                reason=reason,
            )
        except Exception as exc:
            st.error(f"Deactivate failed: {type(exc).__name__}: {exc}")
        else:
            st.success("Whitelist rule deactivated. Existing whitelisted findings were not reverted.")
            st.rerun()


def main() -> None:
    st.set_page_config(page_title="ASM Dashboard", layout="wide")
    if not require_login():
        return
    connection = get_connection()
    page = sidebar_page()
    if page == "Current Status":
        current_status_page(connection)
    elif page == "Historical Results":
        historical_results_page(connection)
    else:
        whitelist_rules_page(connection)


if __name__ == "__main__":
    main()
