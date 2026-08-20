# Risk Distribution Highlight Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Current Status `Risk distribution` chart use a light-green medium color and make rare high-risk slices easier to see.

**Architecture:** Keep the existing `asm_dashboard/app.py` Plotly donut chart and metrics data flow. Update the risk color constant and add a small helper for per-slice pull values, then wire those values into `risk_distribution_figure()`. Extend `test_dashboard_app.py` with focused tests that inspect the generated Plotly figure instead of rendering Streamlit.

**Tech Stack:** Python 3, standard-library `unittest`, pandas, Plotly, Streamlit dashboard module.

## Global Constraints

- Set `medium` to light green `#86efac`, similar to but distinct from `low`.
- Keep `low` as `#16a34a`.
- Keep `high` as `#d62728`.
- Make high-risk slices more visible by pulling them outward from the donut.
- Use a thicker slice separator so small high-risk slices remain easier to spot.
- Show the risk label with the percent on chart text so tiny high slices are identifiable.
- Continue to support unknown or unexpected risk levels through the existing default color fallback.
- Do not change database, metrics, table, dashboard navigation, or scanner behavior.

---

## File Structure

- Modify `asm_dashboard/app.py`: change `RISK_LEVEL_COLORS["medium"]`, add `risk_distribution_pull_values()`, and update `risk_distribution_figure()` trace options.
- Modify `test_dashboard_app.py`: add tests for medium color, high-only pull values, and risk chart label+percent text.

---

### Task 1: Update risk distribution visual encoding

**Files:**
- Modify: `asm_dashboard/app.py:51-57`
- Modify: `asm_dashboard/app.py:301-317`
- Modify: `test_dashboard_app.py:134-163`

**Interfaces:**
- Consumes: `risk: pandas.DataFrame` with columns `risk_level` and `count`.
- Produces: `risk_distribution_pull_values(risk_levels: list[Any]) -> list[float]`.
- Produces: `risk_distribution_figure(risk: pandas.DataFrame) -> plotly.graph_objects.Figure`.

- [ ] **Step 1: Add failing dashboard chart tests**

Add these test methods after `test_exposure_trend_title_and_color` in `test_dashboard_app.py`:

```python
    def test_risk_level_medium_color_is_light_green(self):
        import asm_dashboard.app as app

        self.assertEqual(app.RISK_LEVEL_COLORS["medium"], "#86efac")
        self.assertEqual(app.RISK_LEVEL_COLORS["low"], "#16a34a")
        self.assertNotEqual(app.RISK_LEVEL_COLORS["medium"], app.RISK_LEVEL_COLORS["low"])

    def test_risk_distribution_pulls_only_high_slice(self):
        import asm_dashboard.app as app

        risk = pd.DataFrame(
            [
                {"risk_level": "low", "count": 120},
                {"risk_level": "medium", "count": 40},
                {"risk_level": "high", "count": 1},
                {"risk_level": "unknown", "count": 2},
            ]
        )

        figure = app.risk_distribution_figure(risk)
        trace = figure.data[0]

        self.assertEqual(tuple(trace.marker.colors), ("#16a34a", "#86efac", "#d62728", "#94a3b8"))
        self.assertEqual(tuple(trace.pull), (0, 0, 0.14, 0))
        self.assertEqual(trace.textinfo, "label+percent")
        self.assertEqual(trace.marker.line.width, 3)
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
python3 -m unittest \
  test_dashboard_app.DashboardAppTests.test_risk_level_medium_color_is_light_green \
  test_dashboard_app.DashboardAppTests.test_risk_distribution_pulls_only_high_slice \
  -v
```

Expected: `FAILED`; the medium color is still `#f59e0b`, and the risk distribution trace does not provide pull values or label+percent text.

- [ ] **Step 3: Add minimal implementation**

In `asm_dashboard/app.py`, change the medium color and add the helper immediately before `risk_distribution_figure()`:

```python
RISK_LEVEL_COLORS = {
    "high": "#d62728",
    "medium": "#86efac",
    "low": "#16a34a",
    "unknown": "#94a3b8",
}
```

```python
def risk_distribution_pull_values(risk_levels: list[Any]) -> list[float]:
    return [0.14 if str(level).strip().lower() == "high" else 0 for level in risk_levels]
```

Then update `risk_distribution_figure()` so `update_traces()` includes the new pull values, label+percent text, and thicker separators:

```python
def risk_distribution_figure(risk: pd.DataFrame) -> go.Figure:
    colors = [
        RISK_LEVEL_COLORS.get(str(level).strip().lower(), DEFAULT_RISK_COLOR) for level in risk["risk_level"]
    ]
    pull = risk_distribution_pull_values(list(risk["risk_level"]))
    figure = px.pie(risk, names="risk_level", values="count")
    figure.update_traces(
        hole=0.55,
        sort=False,
        direction="clockwise",
        pull=pull,
        textinfo="label+percent",
        textfont={"color": "#0f172a", "size": 12},
        marker={"colors": colors, "line": {"color": "#ffffff", "width": 3}},
        hovertemplate="%{label}: %{value} (%{percent})<extra></extra>",
    )
    apply_dashboard_chart_style(figure, height=300)
    figure.update_layout(margin={"l": 16, "r": 16, "t": 40, "b": 16})
    return figure
```

- [ ] **Step 4: Run targeted tests to verify they pass**

Run:

```bash
python3 -m unittest \
  test_dashboard_app.DashboardAppTests.test_risk_level_medium_color_is_light_green \
  test_dashboard_app.DashboardAppTests.test_risk_distribution_pulls_only_high_slice \
  -v
```

Expected: `OK`.

- [ ] **Step 5: Run dashboard app tests**

Run:

```bash
python3 -m unittest test_dashboard_app -v
```

Expected: `OK`.

- [ ] **Step 6: Commit the chart update**

Run:

```bash
git add asm_dashboard/app.py test_dashboard_app.py
git commit -m "feat: highlight high risk distribution slice" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 2: Final verification

**Files:**
- Verify: `asm_dashboard/app.py`
- Verify: `test_dashboard_app.py`

**Interfaces:**
- Consumes: `risk_distribution_figure(risk: pandas.DataFrame) -> plotly.graph_objects.Figure` after Task 1.
- Produces: verified repository-level test result for the chart update.

- [ ] **Step 1: Run the full unit test suite**

Run:

```bash
python3 -m unittest -v
```

Expected: `OK`.

- [ ] **Step 2: Inspect the committed diff**

Run:

```bash
git --no-pager diff --stat HEAD~1..HEAD
git --no-pager diff HEAD~1..HEAD -- asm_dashboard/app.py test_dashboard_app.py
```

Expected: the diff only changes the risk distribution medium color, high slice pull behavior, risk chart text/separator styling, and related tests.

- [ ] **Step 3: Commit verification corrections if needed**

If Step 1 or Step 2 required a correction, commit only the corrected chart files:

```bash
git add asm_dashboard/app.py test_dashboard_app.py
git commit -m "fix: stabilize risk distribution highlight" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

If Step 1 and Step 2 pass without corrections, do not create an empty commit.
