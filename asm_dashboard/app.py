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
TABLE_SCROLL_HEIGHT = 5200
ROW_DETAIL_JSON_EXPANDED = True
EXPOSURE_TREND_COLORS = {
    "High Risk": "#d62728",
}
EXPOSURE_TREND_TITLE = "Exposure Trend"
KPI_LABELS = [
    ("Active Attack Surface", "active_findings"),
    ("Active High", "active_high"),
    ("Newly Identified This Month", "newly_identified_this_month"),
    ("Resolved This Quarter", "resolved_this_quarter"),
    ("Sensitive Exposure 80/443", "sensitive_exposure_80_443"),
    ("Current Non-standard Ports", "current_non_standard_ports"),
]
KPI_STYLES = {
    "active_high": {"color": "#d62728", "font_weight": "700"},
}


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
        value = kpis.get(key, 0)
        style = KPI_STYLES.get(key)
        if style:
            cols[index % 3].markdown(
                f"""
                <div data-testid="metric-container">
                    <label>{label}</label>
                    <div style="color: {style['color']}; font-weight: {style['font_weight']}; font-size: 2rem;">{value}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            cols[index % 3].metric(label, value)


def render_current_charts(current_rows: list[dict[str, Any]], trend_rows: list[dict[str, Any]]) -> None:
    trend = metrics.trend_frame(trend_rows)
    left, right = st.columns([2, 1])
    with left:
        st.subheader(EXPOSURE_TREND_TITLE)
        if trend.empty:
            st.info("No trend data available.")
        else:
            figure = px.line(
                trend,
                x="date",
                y="count",
                color="metric",
                markers=True,
                hover_data=["scan_id"],
                color_discrete_map=EXPOSURE_TREND_COLORS,
            )
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
                "Subscription Account Owner": subscription_account_owner(row),
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


def subscription_account_owner(row: dict[str, Any]) -> str:
    value = row.get("tag_emails")
    if isinstance(value, list):
        return ", ".join(str(item) for item in value if item)
    return str(value or "")


def display_date_only(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime.datetime | datetime.date):
        return value.date().isoformat() if isinstance(value, datetime.datetime) else value.isoformat()
    text = str(value).strip()
    return text[:10] if len(text) >= 10 else text


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


def finding_row_model(row: dict[str, Any], page_key: str, index: int) -> dict[str, Any]:
    identity = str(row.get("finding_key") or row.get("id") or f"row-{index}")
    endpoint = str(row.get("endpoint_name") or "").strip()
    endpoint_url = endpoint if endpoint.startswith(("http://", "https://")) else ""
    wiz_url = str(row.get("wiz_link") or "").strip()
    return {
        "identity": identity,
        "expanded_state_key": f"expanded_{page_key}",
        "expand_key": f"expand_{page_key}_{identity}",
        "endpoint_label": endpoint,
        "endpoint_url": endpoint_url,
        "wiz_label": "Wiz Link" if wiz_url else "",
        "wiz_url": wiz_url,
    }


def expand_icon(expanded: bool) -> str:
    return "▼" if expanded else "▶"


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


def render_link(label: str, url: str) -> None:
    if url:
        st.markdown(metrics.markdown_link(label, url))
    else:
        st.write(label)


def render_table_header() -> None:
    columns = st.columns([0.7, 2.8, 0.7, 1.2, 1.6, 1.8, 1.0, 2.4, 1.5, 0.9])
    headers = [
        "Expand",
        "Endpoint Name",
        "Port",
        "Cloud Platform",
        "Cloud Account Name",
        "Subscription Account Owner",
        "Risk Level",
        "Evidence",
        "First Seen At",
        "Wiz Link",
    ]
    for column, header in zip(columns, headers, strict=True):
        column.markdown(f"**{header}**")


def render_finding_row(connection, row: dict[str, Any], page_key: str, index: int, allow_whitelist: bool) -> None:
    model = finding_row_model(row, page_key, index)
    columns = st.columns([0.7, 2.8, 0.7, 1.2, 1.6, 1.8, 1.0, 2.4, 1.5, 0.9])
    is_expanded = st.session_state.get(model["expanded_state_key"]) == model["identity"]
    if columns[0].button(expand_icon(is_expanded), key=model["expand_key"], help="Expand row details"):
        current = st.session_state.get(model["expanded_state_key"])
        st.session_state[model["expanded_state_key"]] = None if current == model["identity"] else model["identity"]
        st.rerun()
    with columns[1]:
        render_link(model["endpoint_label"], model["endpoint_url"])
    columns[2].write(row.get("port") or "")
    columns[3].write(row.get("cloud_platform") or "")
    columns[4].write(row.get("cloud_account_name") or "")
    columns[5].write(subscription_account_owner(row))
    columns[6].write(row.get("risk_level") or "")
    columns[7].write(row.get("evidence") or "")
    columns[8].write(display_date_only(row.get("first_seen_at")))
    with columns[9]:
        render_link(model["wiz_label"], model["wiz_url"])
    if st.session_state.get(model["expanded_state_key"]) == model["identity"]:
        st.markdown("---")
        st.json(row, expanded=ROW_DETAIL_JSON_EXPANDED)
        if allow_whitelist and st.button("Whitelist", key=f"open_whitelist_{page_key}_{model['identity']}"):
            open_whitelist_dialog(connection, row, f"whitelist_{page_key}_{model['identity']}")


def render_finding_table(connection, result: db.PageResult, page_key: str, allow_whitelist: bool) -> None:
    st.caption(f"{result.total} findings, showing page {result.page} with up to {result.page_size} rows.")
    if not result.rows:
        st.info("No findings match the filters.")
        return
    st.markdown(
        """
        <style>
        div[data-testid="stVerticalBlockBorderWrapper"] {
            overflow-x: auto;
        }
        div[data-testid="stHorizontalBlock"] {
            min-width: 1700px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    with st.container(height=TABLE_SCROLL_HEIGHT):
        render_table_header()
        for index, row in enumerate(result.rows, start=1):
            render_finding_row(connection, row, page_key, index, allow_whitelist)


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
    current_rows = db.fetch_current_kpi_rows(connection)
    now = datetime.datetime.now(datetime.UTC)
    month_start = datetime.date(now.year, now.month, 1)
    quarter_start = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=90)
    resolved_this_quarter = db.fetch_resolved_high_count_since(connection, quarter_start)
    kpis = metrics.current_kpis(
        current_rows,
        newly_identified_since=month_start,
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
    st.json(selected, expanded=ROW_DETAIL_JSON_EXPANDED)
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
