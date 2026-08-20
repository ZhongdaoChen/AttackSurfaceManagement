# Risk Distribution Highlight Design

## Purpose

Improve the Current Status `Risk distribution` chart so `medium` appears as a light green similar to `low`, while `high` remains visually prominent even when its count is small.

## Current behavior

`asm_dashboard/app.py` defines risk colors in `RISK_LEVEL_COLORS` and renders the chart in `risk_distribution_figure()`.
The chart uses Plotly Express pie with a donut hole, percent labels, white slice separators, and the existing dashboard chart style.

Current color mapping:

- `high`: red `#d62728`
- `medium`: orange `#f59e0b`
- `low`: green `#16a34a`
- `unknown`: gray `#94a3b8`

When high-risk findings are rare, the high slice can be too thin to notice.

## Required change

Keep the existing donut chart and data flow. Change only the visual encoding:

- Set `medium` to light green `#86efac`, similar to but distinct from `low`.
- Keep `low` as `#16a34a`.
- Keep `high` as `#d62728`.
- Make high-risk slices more visible by pulling them outward from the donut.
- Use a thicker slice separator so small high-risk slices remain easier to spot.
- Show the risk label with the percent on chart text so tiny high slices are identifiable.

The chart should continue to support unknown or unexpected risk levels through the existing default color fallback.

## Testing

Update dashboard app tests to verify:

- `RISK_LEVEL_COLORS["medium"]` is `#86efac`.
- `risk_distribution_figure()` applies a non-zero pull only to high-risk slices.
- The risk distribution trace shows both label and percent text.

No database, metrics, table, dashboard navigation, or scanner behavior changes are required.
