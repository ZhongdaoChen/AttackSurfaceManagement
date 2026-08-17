# Exposure Trend Active High and Cumulative Mitigated Design

## Goal

Update the ASM dashboard Exposure Trend chart so it aligns with the Current Status KPI semantics and shows cumulative mitigation progress.

Success criteria:

- The Exposure Trend `High Risk` line shows the active high-risk count at each scan point.
- The `High Risk` line uses the same active definition as `ASM Current Status / Active High`: `risk_level = 'high'`, `resolved_at IS NULL`, and `whitelisted = FALSE`.
- The Exposure Trend `Mitigated` line is cumulative from the start of the trend window, not only the count mitigated during that scan.
- High-risk findings marked `whitelisted = TRUE` count as mitigated starting from the first scan where they are marked whitelisted, and remain included in later scan points.

## Recommended approach

Compute the trend series in the dashboard database query and keep the metrics layer as a presentation transformer.

`asm_dashboard.db.fetch_trend_rows()` should return one row per scan with:

- `active_high_count`: count of current findings that were already first seen by that scan, last seen at or after that scan, unresolved at that scan, `risk_level = 'high'`, and not whitelisted as of that scan.
- `mitigated_count`: cumulative count of high-risk findings mitigated by that scan, where mitigation means either resolved by that scan or whitelisted by that scan.

`asm_dashboard.metrics.trend_frame()` should map these values directly to chart records:

- `High Risk` = `active_high_count`
- `Mitigated` = `mitigated_count`

It should not subtract mitigated from high risk.

## Data semantics

Current-state lifecycle fields in `asm_current_findings` are the source of truth for resolved lifecycle status:

- `first_seen_at`: when the logical finding first appeared.
- `last_seen_at`: most recent scan where it appeared.
- `resolved_at`: when a finding disappeared from a completed scan.
- `whitelisted`: whether it is currently treated as accepted/mitigated.

Whitelist effective scan should be derived from scan-linked data, not `updated_at`, because `updated_at` changes on later upserts and dashboard whitelist actions can happen between scans. Use the earliest scan timestamp where the logical finding is known to be whitelisted:

- For scan-time or automatic whitelist handling, the earliest matching `asm_findings` row with `whitelisted = TRUE`.
- For dashboard whitelist actions that set `asm_current_findings.resolved_scan_id`, the `asm_scans.started_at` of that `resolved_scan_id`.

The effective whitelist timestamp for a logical finding is the earliest available value from those sources.

For a scan `s.started_at`, active high risk is counted when:

```sql
c.risk_level = 'high'
AND c.first_seen_at <= s.started_at
AND c.last_seen_at >= s.started_at
AND (c.resolved_at IS NULL OR c.resolved_at > s.started_at)
AND (whitelist_effective_at IS NULL OR whitelist_effective_at > s.started_at)
```

Mitigated high risk is counted when:

```sql
c.risk_level = 'high'
AND (
  c.resolved_at <= s.started_at
  OR whitelist_effective_at <= s.started_at
)
```

This intentionally includes whitelisted high-risk findings in `Mitigated`.

## Alternatives considered

1. Compute lifecycle series in SQL. This is recommended because it keeps metric semantics close to the data and avoids loading unnecessary history into Streamlit.
2. Return raw findings and compute a rolling series in Python. This is more flexible, but spreads lifecycle rules across modules and scales worse.
3. Add a persistent scan metric snapshot table. This would support audit snapshots, but it requires schema and writer changes beyond the current need.

## Testing

Update unit tests for:

- `fetch_trend_rows()` SQL filters and aliases.
- `trend_frame()` direct mapping from active/cumulative DB counts to chart records.
- Existing Current Status KPI behavior remains unchanged.
