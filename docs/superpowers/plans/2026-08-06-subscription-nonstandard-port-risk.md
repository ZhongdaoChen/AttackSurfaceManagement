# Subscription Non-Standard Port Risk Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Downgrade non-standard open port findings to low for FDP or `197575089658` subscription/account metadata.

**Architecture:** Add small helper functions in `assess_attack_surface.py` to extract supported subscription/account fields from endpoint data. Keep `NonStandardPortChecker` as the enforcement point so all non-80/443 port findings use the same downgrade logic.

**Tech Stack:** Python 3 standard library, `unittest`.

## Global Constraints

- Default non-standard open ports remain `high`.
- Matching subscription/account values `FDP` and `197575089658` downgrade non-standard open ports to `low`.
- Matching text is case-insensitive.
- Supported metadata fields: `subscription`, `Subscription`, `subscriptionName`, `subscriptionId`, `accountId`, `cloudAccountId`.
- Do not scrape Wiz UI HTML.
- The first regression example is `68.79.15.14:9095` with `subscription = "FDP"`.

---

### Task 1: Add subscription/account downgrade tests

**Files:**
- Modify: `test_assess_attack_surface.py`

**Interfaces:**
- Consumes: `NonStandardPortChecker().check(endpoint, context) -> list[dict[str, Any]]`
- Produces: tests proving FDP and `197575089658` metadata return low and normal endpoints remain high.

- [ ] **Step 1: Write failing FDP test**

Add to `test_assess_attack_surface.py`:

```python
def test_non_standard_open_port_for_fdp_subscription_is_low_risk(self):
    endpoint = {
        "id": "4c8a125f-60e5-50ec-bf5e-7dd14ce98056",
        "name": "68.79.15.14:9095",
        "host": "68.79.15.14",
        "port": 9095,
        "protocols": ["OTHER"],
        "portStatus": "OPEN",
        "exposureLevel": "HIGH",
        "subscription": "FDP",
    }

    findings = asm.NonStandardPortChecker().check(endpoint, asm.CheckContext())

    self.assertEqual(len(findings), 1)
    self.assertEqual(findings[0]["check_id"], "non_standard_open_port")
    self.assertEqual(findings[0]["risk_level"], "low")
    self.assertEqual(findings[0]["details"]["subscription"], "FDP")
```

- [ ] **Step 2: Write failing numeric account test**

Add to `test_assess_attack_surface.py`:

```python
def test_non_standard_open_port_for_exempt_account_id_is_low_risk(self):
    endpoint = {
        "id": "endpoint-1",
        "host": "app.example.com",
        "port": 9095,
        "protocols": ["OTHER"],
        "portStatus": "OPEN",
        "accountId": "197575089658",
    }

    findings = asm.NonStandardPortChecker().check(endpoint, asm.CheckContext())

    self.assertEqual(len(findings), 1)
    self.assertEqual(findings[0]["risk_level"], "low")
    self.assertEqual(findings[0]["details"]["subscription"], "197575089658")
```

- [ ] **Step 3: Run tests to verify they fail**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_non_standard_open_port_for_fdp_subscription_is_low_risk test_assess_attack_surface.AssessAttackSurfaceTests.test_non_standard_open_port_for_exempt_account_id_is_low_risk
```

Expected: FAIL because implementation still returns `high` and no `subscription` detail.

---

### Task 2: Implement subscription/account exception

**Files:**
- Modify: `assess_attack_surface.py`

**Interfaces:**
- Produces: `subscription_value(endpoint: dict[str, Any]) -> str`
- Produces: `is_low_risk_subscription(endpoint: dict[str, Any]) -> bool`

- [ ] **Step 1: Add helper constants and functions**

Add near checker helpers in `assess_attack_surface.py`:

```python
LOW_RISK_SUBSCRIPTIONS = {"fdp", "197575089658"}
SUBSCRIPTION_FIELDS = ("subscription", "Subscription", "subscriptionName", "subscriptionId", "accountId", "cloudAccountId")


def subscription_value(endpoint: dict[str, Any]) -> str:
    for field in SUBSCRIPTION_FIELDS:
        value = endpoint.get(field)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def is_low_risk_subscription(endpoint: dict[str, Any]) -> bool:
    value = subscription_value(endpoint)
    return value.lower() in LOW_RISK_SUBSCRIPTIONS
```

- [ ] **Step 2: Apply helper in `NonStandardPortChecker.check()`**

Change the finding risk and details construction:

```python
subscription = subscription_value(endpoint)
low_risk_subscription = is_low_risk_subscription(endpoint)
return [
    finding(
        endpoint,
        self.check_id,
        "low" if low_risk_subscription else "high",
        f"Open non-standard internet-facing port {port}.",
        (
            "Confirm business need; subscription/account exception lowers priority, but keep the port documented and monitored."
            if low_risk_subscription
            else "Confirm business need; close the port or restrict it with an allowlist, VPN, WAF, or internal load balancer."
        ),
        details={
            "port": port,
            "protocols": endpoint.get("protocols"),
            **({"subscription": subscription} if subscription else {}),
        },
    )
]
```

- [ ] **Step 3: Run focused tests to verify they pass**

Run the two focused tests from Task 1. Expected: PASS.

---

### Task 3: Full validation and commit

**Files:**
- Test: `test_assess_attack_surface.py`
- Test: `test_wiz_auth_poc.py`

**Interfaces:**
- Existing non-standard port test without matching metadata remains high.

- [ ] **Step 1: Run existing normal non-standard port test**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_non_standard_open_port_returns_reduce_finding
```

Expected: PASS and risk remains `high`.

- [ ] **Step 2: Run full tests**

Run:

```bash
python3 -m unittest test_assess_attack_surface.py test_wiz_auth_poc.py
```

Expected: all tests pass.

- [ ] **Step 3: Commit implementation**

Run:

```bash
git add assess_attack_surface.py test_assess_attack_surface.py docs/superpowers/plans/2026-08-06-subscription-nonstandard-port-risk.md
git commit -m "feat: downgrade exempt subscription ports" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```
