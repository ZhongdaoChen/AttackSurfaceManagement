# Whitelist Account Update Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Update the low-risk subscription/account whitelist by removing `odp-china-account` and adding the requested normalized account names.

**Architecture:** Keep the whitelist as the existing `LOW_RISK_SUBSCRIPTIONS` constant in `assess_attack_surface.py`. Preserve current normalization semantics: endpoint subscription/account values are stripped by `subscription_value()` and lowercased by `is_low_risk_subscription()` before set membership checks. Use focused unit tests in `test_assess_attack_surface.py` to prove removed accounts no longer match and new accounts do match.

**Tech Stack:** Python 3, standard-library `unittest`, existing `assess_attack_surface.NonStandardPortChecker`.

## Global Constraints

- `assess_attack_surface.py` stores whitelisted account identifiers in `LOW_RISK_SUBSCRIPTIONS`.
- `subscription_value()` strips leading and trailing whitespace from endpoint subscription/account values.
- `is_low_risk_subscription()` compares the stripped value in lowercase against the whitelist set.
- Remove `odp-china-account`.
- Add normalized lowercase entries: `adidas-linked-tibcochinahub-prod-cn`, `adidas-linked-tibcochinahub-uat-cn`, `adidas-linked-tibcochinahub-sit-cn`, `mobileprintjob production`, `artifactory-china production`, `harbor production`, `harbor staging`, `adidas-linked-harbor-prod-cn`, `adidas-linked-harbor-stg-cn`, `foundation-account`, `wizcnapp-production`, `wizcnapp-development`, `wiz cnapp development`.
- Do not add duplicates for entries already present: `adidas-linked-bam-int-cn`, `adidas-linked-bam-pro-cn`, `adidas-linked-bam-dev-cn`.
- No schema or RDS writer behavior changes are required.

---

## File Structure

- Modify `assess_attack_surface.py`: update only `LOW_RISK_SUBSCRIPTIONS`.
- Modify `test_assess_attack_surface.py`: replace the ODP low-risk test with a high-risk test and add coverage for all new whitelist entries.

---

### Task 1: Update whitelist behavior and tests

**Files:**
- Modify: `assess_attack_surface.py`
- Modify: `test_assess_attack_surface.py`

**Interfaces:**
- Consumes: `asm.NonStandardPortChecker().check(endpoint: dict[str, Any], context: asm.CheckContext) -> list[dict[str, Any]]`.
- Consumes: `LOW_RISK_SUBSCRIPTIONS: set[str]`.
- Produces: whitelist membership matching the approved spec.

- [ ] **Step 1: Replace the ODP low-risk test**

Replace the existing `test_non_standard_open_port_for_odp_china_account_is_low_risk` method in `test_assess_attack_surface.py` with:

```python
    def test_non_standard_open_port_for_odp_china_account_is_high_risk(self):
        endpoint = {
            "id": "endpoint-1",
            "host": "app.example.com",
            "port": 22,
            "protocols": ["SSH"],
            "portStatus": "OPEN",
            "cloudAccount": {"name": "ODP-China-account"},
        }

        def fetcher(request, timeout, context=None):
            raise asm.urllib.error.URLError("connection refused")

        findings = asm.NonStandardPortChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["risk_level"], "high")
        self.assertEqual(findings[0]["details"]["subscription"], "ODP-China-account")
```

- [ ] **Step 2: Add the new whitelist entries test**

Add this method immediately after the ODP test in `test_assess_attack_surface.py`:

```python
    def test_non_standard_open_port_for_new_whitelisted_accounts_is_low_risk(self):
        accounts = [
            "adidas-linked-tibcochinahub-prod-cn",
            "adidas-linked-tibcochinahub-uat-cn",
            "adidas-linked-tibcochinahub-sit-cn",
            "mobileprintjob Production",
            "artifactory-china Production",
            "Harbor Production",
            "harbor Staging",
            "adidas-linked-harbor-prod-cn",
            "adidas-linked-harbor-stg-cn",
            "Foundation-account",
            "wizcnapp-Production",
            "wizcnapp-Development",
            "Wiz CNAPP Development ",
            "Wiz CNAPP Development",
        ]

        def fetcher(request, timeout, context=None):
            raise asm.urllib.error.URLError("connection refused")

        for account in accounts:
            with self.subTest(account=account):
                endpoint = {
                    "id": "endpoint-1",
                    "host": "app.example.com",
                    "port": 22,
                    "protocols": ["SSH"],
                    "portStatus": "OPEN",
                    "cloudAccount": {"name": account},
                }

                findings = asm.NonStandardPortChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["risk_level"], "low")
                self.assertEqual(findings[0]["details"]["subscription"], account.strip())
```

- [ ] **Step 3: Run the behavior tests and verify they fail**

Run:

```bash
python3 -m unittest \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_non_standard_open_port_for_odp_china_account_is_high_risk \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_non_standard_open_port_for_new_whitelisted_accounts_is_low_risk \
  -v
```

Expected: `FAILED`; ODP still returns `low`, and the new account subtests return `high`.

- [ ] **Step 4: Update the whitelist constant**

Replace the current `LOW_RISK_SUBSCRIPTIONS` block in `assess_attack_surface.py` with:

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
    "adidas-linked-tibcochinahub-prod-cn",
    "adidas-linked-tibcochinahub-uat-cn",
    "adidas-linked-tibcochinahub-sit-cn",
    "mobileprintjob production",
    "artifactory-china production",
    "harbor production",
    "harbor staging",
    "adidas-linked-harbor-prod-cn",
    "adidas-linked-harbor-stg-cn",
    "foundation-account",
    "wizcnapp-production",
    "wizcnapp-development",
    "wiz cnapp development",
}
```

- [ ] **Step 5: Run the targeted tests and verify they pass**

Run:

```bash
python3 -m unittest \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_non_standard_open_port_for_odp_china_account_is_high_risk \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_non_standard_open_port_for_new_whitelisted_accounts_is_low_risk \
  -v
```

Expected: `OK`.

- [ ] **Step 6: Run all attack surface tests**

Run:

```bash
python3 -m unittest test_assess_attack_surface -v
```

Expected: `OK`.

- [ ] **Step 7: Commit the whitelist update**

Run:

```bash
git add assess_attack_surface.py test_assess_attack_surface.py
git commit -m "feat: update low risk account whitelist" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 2: Final verification

**Files:**
- Verify: `assess_attack_surface.py`
- Verify: `test_assess_attack_surface.py`

**Interfaces:**
- Consumes: Task 1.
- Produces: verified whitelist behavior.

- [ ] **Step 1: Run the full unit test suite**

Run:

```bash
python3 -m unittest -v
```

Expected: `OK`.

- [ ] **Step 2: Inspect the whitelist diff**

Run:

```bash
git --no-pager diff --stat HEAD~1..HEAD
git --no-pager diff HEAD~1..HEAD -- assess_attack_surface.py test_assess_attack_surface.py
```

Expected: the diff only removes `odp-china-account`, adds the approved whitelist entries, and adds/updates whitelist tests.

- [ ] **Step 3: Commit verification corrections if needed**

If Step 1 or Step 2 required a correction, commit only the corrected whitelist files:

```bash
git add assess_attack_surface.py test_assess_attack_surface.py
git commit -m "fix: stabilize whitelist account update" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

If Step 1 and Step 2 pass without corrections, do not create an empty commit.
