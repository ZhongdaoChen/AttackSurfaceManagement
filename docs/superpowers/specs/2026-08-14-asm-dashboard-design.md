# ASM Streamlit Dashboard Design

## Goal

Build a clear, professional Streamlit dashboard for CISO-level Attack Surface Management visibility. The dashboard reads from the existing RDS PostgreSQL database and focuses on current exposure status, risk movement, non-standard port trends, sensitive information exposure, and actionable finding triage.

The first implementation is a production-usable internal dashboard, not only an exploratory notebook. It should still stay lightweight enough to ship quickly with Streamlit.

## Users and success criteria

Primary users are CISO/AppSec leadership and AppSec operators.

Success criteria:

- The default page answers whether the attack surface is improving or worsening.
- Current active risk is visible without navigating away from the landing page.
- Operators can filter, inspect, and whitelist findings from the same dashboard.
- Historical scan results remain available, but do not clutter the main page.
- Whitelist decisions are auditable and automatically applied to future scans for the same endpoint and port.

## Recommended approach

Use a single Streamlit app with separated Python modules:

- App entry and navigation.
- RDS connection/config loading.
- Query functions.
- Metric and trend aggregation.
- Chart/table rendering.
- Whitelist mutation functions.

This keeps delivery fast while avoiding a single large Streamlit file that would be hard to test or migrate later.

## Dependencies and configuration

Add these runtime dependencies:

- `streamlit`
- `pandas`
- `plotly`

Configuration:

- Reuse the existing `RDS_*` environment variables and `.env` loading pattern.
- Use `DASHBOARD_PASSWORD` for simple password protection.
- Do not store passwords or RDS secrets in source code.

If `DASHBOARD_PASSWORD` is absent, the app should fail closed and show a clear configuration error rather than running unauthenticated.

## Data sources

The dashboard reads the existing tables:

- `asm_scans`
- `asm_findings`
- `asm_current_findings`

Add a dashboard-managed table for whitelist rules:

```sql
CREATE TABLE IF NOT EXISTS asm_whitelist_rules (
  id BIGSERIAL PRIMARY KEY,
  endpoint_name TEXT NOT NULL,
  port INTEGER,
  reason TEXT NOT NULL,
  operator_name TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deactivated_at TIMESTAMPTZ,
  deactivated_by TEXT,
  deactivation_reason TEXT
);
```

Add indexes for active rule lookup by endpoint and port.

The latest scan is the `asm_scans` row with the greatest `started_at`. If multiple scans have the same timestamp, use the lexicographically greatest `scan_id` as a deterministic tie-breaker.

## Whitelist semantics

Dashboard whitelist rules match by `endpoint_name + port`.

When a user whitelists a selected current finding:

1. Prompt for reason and operator name.
2. Insert an active row into `asm_whitelist_rules`.
3. Update matching `asm_current_findings` rows to `whitelisted = TRUE`.
4. Update all matching historical `asm_findings` rows to `whitelisted = TRUE`.

Future scans must automatically apply active dashboard whitelist rules. The scanner/RDS writer should check active `asm_whitelist_rules` by `endpoint_name + port` and set `whitelisted = TRUE` for matching findings.

The Whitelist Rules page allows viewing and deactivating rules. Deactivation only stops future automatic whitelist matching. It does not revert existing `asm_current_findings` or `asm_findings` rows already marked as whitelisted.

## Navigation and page structure

Use Streamlit sidebar navigation:

1. Current Status
2. Historical Results
3. Whitelist Rules

`Current Status` is the default landing page.

`Historical Results` is intentionally not shown on the main dashboard because it is used less frequently.

## Current Status page

Current Status shows only active, non-whitelisted rows:

```sql
FROM asm_current_findings
WHERE resolved_at IS NULL
  AND whitelisted = FALSE
```

### KPI cards

Show six top-level KPI cards:

1. Active Findings
2. Active High
3. New Latest Scan
4. Resolved Latest Scan
5. Sensitive Exposure on 80/443
6. Current Non-standard Ports

Metric definitions:

- Active Findings: active non-whitelisted current findings.
- Active High: active non-whitelisted current findings with `risk_level = 'high'`.
- New Latest Scan: active non-whitelisted current findings whose `first_seen_scan_id` is the latest scan.
- Resolved Latest Scan: findings resolved by the latest scan using `resolved_scan_id`.
- Sensitive Exposure on 80/443: active non-whitelisted current findings where `check_id = 'llm_sensitive_content'` and `port IN (80, 443)`.
- Current Non-standard Ports: active non-whitelisted current findings where `check_id = 'non_standard_open_port'`.

### Charts

Default trend window is all history, aggregated by `asm_scans.started_at` date.

Trend definitions:

- New count: findings whose `first_seen_at` falls on the date.
- Resolved count: findings whose `resolved_at` falls on the date.
- Active count for a date: findings whose `first_seen_at` is on or before that date and whose `resolved_at` is null or after that date.
- High Risk count: active count restricted to `risk_level = 'high'`.

Show:

- Active/New/Resolved/High Risk trend line.
- Non-standard port trend using `check_id = 'non_standard_open_port'`.
- Sensitive exposure trend using `check_id = 'llm_sensitive_content'` and `port IN (80, 443)`.
- Risk level distribution pie.
- Cloud account risk concentration.
- Cloud platform distribution.
- Top Check IDs.

The page narrative should emphasize whether exposure is improving or worsening.

### Current findings list

Default page size is 200 rows.

Columns:

- Endpoint Name, rendered as a hyperlink to the endpoint value when it is a URL.
- Port
- Cloud Platform
- Cloud Account Name
- Risk Level
- Evidence
- First Seen At

Optional visible columns may include Check ID and Exposure Level if space allows.

Filters:

- Multi-select `risk_level`
- Multi-select `port`
- Multi-select `cloud_platform`
- Multi-select `cloud_account_name`
- Multi-select `check_id`
- Multi-select `exposure_level`
- Endpoint/host text search
- First seen date range

Row detail interaction:

- Use Streamlit row selection.
- Show a detail panel below the table for the selected row.
- The detail panel displays all row fields, including raw/details JSON where available.
- The whitelist action applies to the selected row.

## Historical Results page

Historical Results uses `asm_scans.started_at` as the date basis.

Users choose a date. The page shows all `asm_findings` rows for scans started on that date, including whitelisted findings.

Historical Results uses the same general table format and filters as Current Status, plus historical context columns:

- `scan_id`
- scan started at

Historical rows should include First Seen At when it can be resolved by matching the historical finding to `asm_current_findings` with the same logical identity fields: `endpoint_id`, `check_id`, `host`, and `port`. If no matching current row exists, show the scan started timestamp as the observation time and label it clearly as scan time in the detail panel.

The page should include summary cards for:

- Scans on selected date
- Total findings
- High findings
- Whitelisted findings

## Whitelist Rules page

Show dashboard-created whitelist rules with:

- Endpoint Name
- Port
- Reason
- Operator Name
- Active status
- Created At
- Deactivated At
- Deactivated By
- Deactivation Reason

Allow users to deactivate active rules. Deactivation requires operator name and reason.

Deactivation updates only the rule metadata. It does not update existing findings back to non-whitelisted.

## Error handling

- Missing `DASHBOARD_PASSWORD`: show a clear configuration error and do not render data.
- Missing RDS configuration: show a clear configuration error.
- RDS connection/query failure: show an actionable error without exposing credentials.
- Whitelist insert/update failure: show the failure and do not present it as successful.
- Avoid broad silent catches. Errors should be visible in Streamlit and logs.

## Testing strategy

Use unit tests for:

- RDS config loading reuse.
- Query SQL construction for current status filters.
- Metric aggregation from representative rows.
- Whitelist rule insert and update behavior.
- Automatic whitelist matching in the RDS writer for future scans.
- Authentication gate behavior.

Use fake connection/cursor objects where possible so tests do not require RDS network access.

Manual validation:

- Run the Streamlit app locally with test environment variables.
- Confirm login blocks access without the password.
- Confirm Current Status excludes resolved and whitelisted rows.
- Confirm Historical Results includes whitelisted rows.
- Confirm whitelist creation writes a rule and updates current/history rows.
- Confirm rule deactivation does not revert existing findings.

## Out of scope

- SSO or per-user enterprise authentication.
- A separate API backend.
- Real-time streaming updates.
- Editing arbitrary finding fields from the dashboard.
- Automatically reverting historical whitelist flags after rule deactivation.
