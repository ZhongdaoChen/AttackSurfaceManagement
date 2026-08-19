from __future__ import annotations

import datetime
import html
import os
import re
import sys
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from asm_dashboard import auth, db, metrics
from assess_attack_surface import load_dotenv


PAGE_SIZE = 200
TABLE_SCROLL_HEIGHT = 620
ROW_DETAIL_JSON_EXPANDED = True
EXPOSURE_TREND_COLORS = {
    "High Risk": "#d62728",
    "Mitigated": "#1f77b4",
}
EXPOSURE_TREND_TITLE = "Exposure Trend"
CHART_SECTION_DIVIDER_HTML = '<div style="width: 100%; border-top: 1px solid #e5e7eb; border-top-color: light-dark(#e5e7eb, #3d4351); margin: 1.25rem 0 1rem 0;"></div>'
KPI_LABELS = [
    ("Active Attack Surface", "active_findings"),
    ("Active High", "active_high"),
    ("Newly Identified This Month", "newly_identified_this_month"),
    ("Cumulative Mitigated", "cumulative_mitigated"),
    ("Sensitive Exposure 80/443", "sensitive_exposure_80_443"),
    ("Current Non-standard Ports", "current_non_standard_ports"),
]
KPI_STYLES = {
    "active_high": {"color": "#d62728", "font_weight": "700"},
}
KPI_ACCENTS = {
    "active_findings": "#2563eb",
    "active_high": "#d62728",
    "newly_identified_this_month": "#d97706",
    "cumulative_mitigated": "#16a34a",
    "sensitive_exposure_80_443": "#ea580c",
    "current_non_standard_ports": "#7c3aed",
}
DEFAULT_KPI_ACCENT = "#2563eb"
RISK_LEVEL_COLORS = {
    "high": "#d62728",
    "medium": "#f59e0b",
    "low": "#16a34a",
    "unknown": "#94a3b8",
}
DEFAULT_RISK_COLOR = "#cbd5e1"
BAR_CHART_ACCENTS = {
    "cloud_account_name": "#2563eb",
    "cloud_platform": "#0ea5e9",
    "check_id": "#6366f1",
}
DEFAULT_BAR_ACCENT = "#6366f1"
DASHBOARD_LAYOUT_CSS = """
<style>
/* Pull the page content up so KPIs and filters fit the first viewport
   on a full-screen MacBook display. */
.block-container {
    padding-top: 1.25rem;
    padding-bottom: 2rem;
}
/* Tighter widget spacing so the filter bank stays compact. */
[data-testid="stWidgetLabel"] {
    margin-bottom: 0.2rem;
}
[data-testid="stExpander"] [data-testid="stVerticalBlock"] {
    gap: 0.5rem;
}
div[data-testid="stMainBlockContainer"] h1 {
    font-size: 1.9rem;
    margin-bottom: 0.25rem;
}
.asm-kpi-card {
    position: relative;
    background-color: #f0f2f6;
    background-color: light-dark(#f0f2f6, #262729);
    border: 1px solid rgba(120, 127, 140, 0.28);
    border: 1px solid light-dark(rgba(49, 51, 63, 0.2), rgba(250, 250, 250, 0.2));
    border-radius: 10px;
    padding: 10px 14px 10px 18px;
    overflow: hidden;
    color: inherit;
    transition: box-shadow 0.2s ease, transform 0.2s ease;
}
.asm-kpi-card:hover {
    box-shadow: 0 6px 18px rgba(0, 0, 0, 0.15);
    transform: translateY(-2px);
}
.asm-kpi-card--alert {
    background-image: linear-gradient(rgba(239, 68, 68, 0.07), rgba(239, 68, 68, 0.07));
    border-color: rgba(220, 38, 38, 0.5);
}
.asm-kpi-accent {
    position: absolute;
    left: 0;
    top: 0;
    bottom: 0;
    width: 4px;
}
.asm-kpi-label {
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: 0.02em;
    line-height: 1.35;
    color: inherit;
    opacity: 0.62;
    margin-bottom: 4px;
}
.asm-kpi-value {
    font-size: 1.55rem;
    line-height: 1.1;
    color: inherit;
    font-variant-numeric: tabular-nums;
}
</style>
"""


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


def capitalize_option_label(value: Any) -> str:
    text = str(value)
    return re.sub(r"(^|[\s_\-])(\w)", lambda match: match.group(1) + match.group(2).upper(), text)


def filter_state(options: dict[str, list[Any]], key_prefix: str = "current") -> db.FilterState:
    with st.expander("Filters", expanded=True):
        row1_col1, row1_col2, row1_col3, row1_col4 = st.columns(4)
        with row1_col1:
            risk_levels = st.multiselect(
                "Risk Level",
                options.get("risk_levels", []),
                key=f"{key_prefix}_risk",
                format_func=capitalize_option_label,
            )
        with row1_col2:
            ports = st.multiselect("Port", options.get("ports", []), key=f"{key_prefix}_port")
        with row1_col3:
            cloud_platforms = st.multiselect(
                "Cloud Platform",
                options.get("cloud_platforms", []),
                key=f"{key_prefix}_platform",
                format_func=capitalize_option_label,
            )
        with row1_col4:
            cloud_accounts = st.multiselect(
                "Cloud Account Name",
                options.get("cloud_accounts", []),
                key=f"{key_prefix}_account",
                format_func=capitalize_option_label,
            )
        row2_col1, row2_col2, row2_col3, row2_col4 = st.columns(4)
        with row2_col1:
            check_ids = st.multiselect(
                "Check ID",
                options.get("check_ids", []),
                key=f"{key_prefix}_check",
                format_func=capitalize_option_label,
            )
        with row2_col2:
            exposure_levels = st.multiselect(
                "Exposure Level",
                options.get("exposure_levels", []),
                key=f"{key_prefix}_exposure",
                format_func=capitalize_option_label,
            )
        with row2_col3:
            search = st.text_input("Endpoint or host search", key=f"{key_prefix}_search")
        with row2_col4:
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


def kpi_card_html(label: str, value: int, key: str) -> str:
    style = KPI_STYLES.get(key) or {}
    accent = KPI_ACCENTS.get(key, DEFAULT_KPI_ACCENT)
    value_color = style.get("color", "inherit")
    value_weight = style.get("font_weight", "700")
    card_class = "asm-kpi-card asm-kpi-card--alert" if key == "active_high" else "asm-kpi-card"
    escaped_label = html.escape(label)
    return (
        f'<div class="{card_class}" data-testid="metric-container">'
        f'<div class="asm-kpi-accent" style="background-color: {accent};"></div>'
        f'<div class="asm-kpi-label" title="{escaped_label}">{escaped_label}</div>'
        f'<div class="asm-kpi-value" style="color: {value_color}; font-weight: {value_weight};">{value}</div>'
        "</div>"
    )


def render_kpis(kpis: dict[str, int]) -> None:
    cols = st.columns(len(KPI_LABELS), gap="small")
    for index, (label, key) in enumerate(KPI_LABELS):
        value = kpis.get(key, 0)
        cols[index].markdown(kpi_card_html(label, value, key), unsafe_allow_html=True)


def apply_dashboard_chart_style(figure: go.Figure, height: int | None = None) -> None:
    """Apply structural chart styling only.

    Colors (backgrounds, gridlines, fonts, hover labels) are intentionally
    left unset so Streamlit's built-in plotly theming supplies values that
    follow the active light/dark theme.
    """
    figure.update_layout(
        height=height,
        margin={"l": 48, "r": 16, "t": 32, "b": 16},
        legend={
            "orientation": "h",
            "yanchor": "bottom",
            "y": 1.02,
            "xanchor": "right",
            "x": 1,
            "bgcolor": "rgba(0,0,0,0)",
        },
    )
    figure.update_xaxes(showgrid=False)
    figure.update_yaxes(zeroline=False)


def exposure_trend_figure(trend: pd.DataFrame):
    figure = go.Figure()
    for metric in ("High Risk", "Mitigated"):
        subset = trend[trend["metric"] == metric]
        if subset.empty:
            continue
        figure.add_trace(
            go.Scatter(
                x=subset["date"],
                y=subset["count"],
                mode="lines+markers",
                name=metric,
                marker={
                    "color": EXPOSURE_TREND_COLORS[metric],
                    "size": 7,
                    "line": {"color": "#ffffff", "width": 1.5},
                },
                line={"color": EXPOSURE_TREND_COLORS[metric], "width": 2.5},
                yaxis="y",
                customdata=subset[["scan_id"]],
                hovertemplate="%{x}<br>%{fullData.name}: %{y}<br>scan_id: %{customdata[0]}<extra></extra>",
            )
        )
    figure.update_xaxes(dtick="D1", tickformat="%Y-%m-%d")
    figure.update_yaxes(title_text="Count", rangemode="nonnegative")
    apply_dashboard_chart_style(figure, height=300)
    figure.update_layout(hovermode="x unified")
    return figure


def risk_distribution_figure(risk: pd.DataFrame) -> go.Figure:
    colors = [
        RISK_LEVEL_COLORS.get(str(level).strip().lower(), DEFAULT_RISK_COLOR) for level in risk["risk_level"]
    ]
    figure = px.pie(risk, names="risk_level", values="count")
    figure.update_traces(
        hole=0.55,
        sort=False,
        direction="clockwise",
        textinfo="percent",
        textfont={"color": "#0f172a", "size": 12},
        marker={"colors": colors, "line": {"color": "#ffffff", "width": 2}},
        hovertemplate="%{label}: %{value} (%{percent})<extra></extra>",
    )
    apply_dashboard_chart_style(figure, height=300)
    figure.update_layout(margin={"l": 16, "r": 16, "t": 40, "b": 16})
    return figure


def distribution_bar_figure(frame: pd.DataFrame, key: str) -> go.Figure:
    figure = px.bar(frame, x=key, y="count")
    accent = BAR_CHART_ACCENTS.get(key, DEFAULT_BAR_ACCENT)
    figure.update_traces(
        marker_color=accent,
        marker={"line": {"width": 0}},
        text=frame["count"],
        textposition="outside",
        cliponaxis=False,
        hovertemplate="%{x}: %{y}<extra></extra>",
    )
    figure.update_xaxes(title=None)
    figure.update_yaxes(title=None)
    if key == "check_id":
        figure.update_xaxes(tickangle=-35, tickfont={"size": 10})
    apply_dashboard_chart_style(figure, height=260)
    return figure


def render_current_charts(current_rows: list[dict[str, Any]], trend_rows: list[dict[str, Any]]) -> None:
    trend = metrics.trend_frame(trend_rows)
    left, right = st.columns([2, 1])
    with left:
        with st.container(border=True):
            st.subheader(EXPOSURE_TREND_TITLE)
            if trend.empty:
                st.info("No trend data available.")
            else:
                st.plotly_chart(exposure_trend_figure(trend), use_container_width=True)
    with right:
        with st.container(border=True):
            st.subheader("Risk distribution")
            risk = metrics.distribution(current_rows, "risk_level")
            if risk.empty:
                st.info("No risk distribution data.")
            else:
                st.plotly_chart(risk_distribution_figure(risk), use_container_width=True)
    col1, col2, col3 = st.columns(3)
    for column, title, key in [
        (col1, "Cloud Accounts", "cloud_account_name"),
        (col2, "Cloud Platforms", "cloud_platform"),
        (col3, "Top Check IDs", "check_id"),
    ]:
        with column:
            with st.container(border=True):
                st.subheader(title)
                frame = metrics.distribution(current_rows, key)
                if frame.empty:
                    st.info("No data.")
                else:
                    st.plotly_chart(distribution_bar_figure(frame, key), use_container_width=True)


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


def evidence_cell_html(value: Any) -> str:
    escaped = html.escape(str(value or ""))
    return (
        '<div style="display: -webkit-box; -webkit-line-clamp: 2; '
        '-webkit-box-orient: vertical; overflow: hidden; text-overflow: ellipsis;">'
        f"{escaped}</div>"
    )


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
    columns[7].markdown(evidence_cell_html(row.get("evidence")), unsafe_allow_html=True)
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
        /* Scope the wide-table horizontal scroll to the findings scroll
           container (marked by .asm-table-scroller) so KPI, filter, and
           chart rows keep the viewport width. The direct-child chain
           matches only the scroll block, never the page root block. */
        div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] > div[data-testid="stMarkdown"] .asm-table-scroller) {
            overflow-x: auto;
        }
        div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] > div[data-testid="stMarkdown"] .asm-table-scroller) div[data-testid="stHorizontalBlock"] {
            min-width: 1700px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    with st.container(height=TABLE_SCROLL_HEIGHT):
        st.markdown('<div class="asm-table-scroller"></div>', unsafe_allow_html=True)
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
    trend_rows = db.fetch_trend_rows(connection)
    kpis = metrics.current_kpis(
        current_rows,
        newly_identified_since=month_start,
        cumulative_mitigated=metrics.cumulative_mitigated_count(trend_rows),
    )
    render_kpis(kpis)
    options = db.fetch_filter_options(connection, current_only=True)
    filters = filter_state(options, key_prefix="current")
    st.markdown(CHART_SECTION_DIVIDER_HTML, unsafe_allow_html=True)
    render_current_charts(current_rows, trend_rows)
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
    header = st.columns([0.8, 2.8, 0.8, 1.0, 2.4, 1.5, 1.5])
    for column, title in zip(
        header,
        ["Details", "Endpoint Name", "Port", "Active", "Reason", "Operator Name", "Created At"],
        strict=True,
    ):
        column.markdown(f"**{title}**")
    for index, rule in enumerate(rules, start=1):
        identity = str(rule.get("id") or index)
        expanded_key = "expanded_whitelist_rule"
        columns = st.columns([0.8, 2.8, 0.8, 1.0, 2.4, 1.5, 1.5])
        is_expanded = st.session_state.get(expanded_key) == identity
        if columns[0].button(expand_icon(is_expanded), key=f"expand_whitelist_rule_{identity}"):
            st.session_state[expanded_key] = None if is_expanded else identity
            st.rerun()
        columns[1].write(rule.get("endpoint_name") or "")
        columns[2].write(rule.get("port") or "")
        columns[3].write("Yes" if rule.get("active") else "No")
        columns[4].write(rule.get("reason") or "")
        columns[5].write(rule.get("operator_name") or "")
        columns[6].write(display_date_only(rule.get("created_at")))
        if st.session_state.get(expanded_key) != identity:
            continue
        st.json(rule, expanded=ROW_DETAIL_JSON_EXPANDED)
        if not rule.get("active"):
            st.info("This rule is already inactive.")
            continue
        with st.form(f"deactivate_rule_{identity}"):
            operator_name = st.text_input("Operator name")
            reason = st.text_area("Deactivation reason")
            submitted = st.form_submit_button("Deactivate rule")
        if submitted:
            try:
                db.deactivate_whitelist_rule(
                    connection,
                    rule_id=int(rule["id"]),
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
    st.markdown(DASHBOARD_LAYOUT_CSS, unsafe_allow_html=True)
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
