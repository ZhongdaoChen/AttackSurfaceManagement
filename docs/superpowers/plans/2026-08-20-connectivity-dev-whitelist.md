# Connectivity-Dev Whitelist Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `Connectivity-Dev Development` and `014826645533` to the low-risk subscription/account whitelist for fallback non-standard open port findings.

**Architecture:** Keep the whitelist in the existing `LOW_RISK_SUBSCRIPTIONS` constant in `assess_attack_surface.py`. Preserve the current normalization path: `subscription_value()` strips endpoint account values, and `is_low_risk_subscription()` lowercases before set lookup. Add focused unit coverage for the account display name and numeric account ID.

**Tech Stack:** Python 3, standard-library `unittest`, existing `assess_attack_surface.NonStandardPortChecker`.

## Global Constraints

- Add normalized whitelist entry `connectivity-dev development`.
- Add whitelist entry `014826645533`.
- Do not change schema, RDS writer, dashboard, or endpoint+port whitelist behavior.
- Preserve original extracted subscription/account values in finding details.
- Use the existing `LOW_RISK_SUBSCRIPTIONS` constant and existing normalization behavior.

---

## File Structure

- Modify `assess_attack_surface.py`: add the two requested normalized entries to `LOW_RISK_SUBSCRIPTIONS`.
- Modify `test_assess_attack_surface.py`: add one focused test method that checks the requested account name and account ID.

---

### Task 1: Add Connectivity-Dev whitelist entries

**Files:**
- Modify: `assess_attack_surface.py:35-49`
- Modify: `test_assess_attack_surface.py:196-232`

**Interfaces:**
- Consumes: `asm.NonStandardPortChecker().check(endpoint: dict[str, Any], context: asm.CheckContext) -> list[dict[str, Any]]`.
- Consumes: `LOW_RISK_SUBSCRIPTIONS: set[str]`.
- Produces: `connectivity-dev development` and `014826645533` membership in `LOW_RISK_SUBSCRIPTIONS`.

- [ ] **Step 1: Add the failing whitelist behavior test**

Add this method after `test_non_standard_open_port_for_mobileprintjob_account_id_is_low_risk` in `test_assess_attack_surface.py`:

```python
    def test_non_standard_open_port_for_connectivity_dev_accounts_is_low_risk(self):
        cases = [
            ("cloudAccount", {"name": "Connectivity-Dev Development"}, "Connectivity-Dev Development"),
            ("accountId", "014826645533", "014826645533"),
        ]

        def fetcher(request, timeout, context=None):
            raise asm.urllib.error.URLError("connection refused")

        for field, value, expected_subscription in cases:
            with self.subTest(field=field, value=value):
                endpoint = {
                    "id": "endpoint-1",
                    "host": "app.example.com",
                    "port": 22,
                    "protocols": ["SSH"],
                    "portStatus": "OPEN",
                    field: value,
                }

                findings = asm.NonStandardPortChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["risk_level"], "low")
                self.assertEqual(findings[0]["details"]["subscription"], expected_subscription)
```

- [ ] **Step 2: Run the targeted test to verify it fails**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_non_standard_open_port_for_connectivity_dev_accounts_is_low_risk -v
```

Expected: `FAILED`; each subtest returns `risk_level` of `high` because neither identifier is in `LOW_RISK_SUBSCRIPTIONS` yet.

- [ ] **Step 3: Add the requested whitelist entries**

Update `LOW_RISK_SUBSCRIPTIONS` in `assess_attack_surface.py` so the block contains the two new entries:

```python
LOW_RISK_SUBSCRIPTIONS = {
    "fdp",
    "197575089658",
    "adidas-linked-bam-pro-cn",
    "347233338954",
    "adidas-linked-tbm-cn",
    "482708397438",
    "adidas-linked-bam-dev-cn",
    "347077314801",
    "adidas-linked-bam-int-cn",
    "347221608445",
    "cicdtools-prod",
    "mobileprintjob production",
    "251239237414",
    "connectivity-dev development",
    "014826645533",
}
```

- [ ] **Step 4: Run the targeted test to verify it passes**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_non_standard_open_port_for_connectivity_dev_accounts_is_low_risk -v
```

Expected: `OK`.

- [ ] **Step 5: Run the attack surface unit tests**

Run:

```bash
python3 -m unittest test_assess_attack_surface -v
```

Expected: `OK`.

- [ ] **Step 6: Commit the whitelist update**

Run:

```bash
git add assess_attack_surface.py test_assess_attack_surface.py
git commit -m "feat: add connectivity dev whitelist entries" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 2: Final verification

**Files:**
- Verify: `assess_attack_surface.py`
- Verify: `test_assess_attack_surface.py`

**Interfaces:**
- Consumes: `LOW_RISK_SUBSCRIPTIONS` after Task 1.
- Produces: verified repository-level test result for the whitelist update.

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
git --no-pager diff HEAD~1..HEAD -- assess_attack_surface.py test_assess_attack_surface.py
```

Expected: the diff only adds `connectivity-dev development`, `014826645533`, and the focused unit test for those two entries.

- [ ] **Step 3: Commit verification corrections if needed**

If Step 1 or Step 2 required a correction, commit only the corrected whitelist files:

```bash
git add assess_attack_surface.py test_assess_attack_surface.py
git commit -m "fix: stabilize connectivity dev whitelist entries" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

If Step 1 and Step 2 pass without corrections, do not create an empty commit.
