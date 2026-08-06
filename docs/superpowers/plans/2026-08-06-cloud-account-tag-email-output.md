# Cloud Account Tag Email Output Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Output email-like strings from CloudAccount/Subscription tags into JSONL and CSV findings.

**Architecture:** Add CloudAccount GraphEntity tag email lookup helpers to `wiz_auth_poc.py`, cache lookups by `cloudAccount.id` in default Wiz-fetch scan mode, and add `tagEmails` / `TagEmails` output fields in `assess_attack_surface.py`.

**Tech Stack:** Python 3 standard library, Wiz GraphQL, `unittest`.

## Global Constraints

- Do not scrape Wiz UI.
- Extract emails from `graphEntity(id: cloudAccount.id).properties` and `.providerData`.
- Cache by `cloudAccount.id`.
- JSONL field is `tagEmails`.
- CSV column is `TagEmails`.
- `--input` mode does not call Wiz and only outputs `tagEmails` already present in input.

---

### Task 1: Add Wiz tag email helpers

**Files:** `wiz_auth_poc.py`, `test_wiz_auth_poc.py`

- [ ] Write tests for recursive email extraction and `fetch_cloud_account_tag_emails()`.
- [ ] Verify tests fail.
- [ ] Implement `extract_email_values()` and `fetch_cloud_account_tag_emails(config, token, cloud_account_id)`.
- [ ] Verify focused tests pass.

### Task 2: Add output fields and enrichment

**Files:** `assess_attack_surface.py`, `test_assess_attack_surface.py`

- [ ] Write tests for JSONL finding `tagEmails` and CSV `TagEmails`.
- [ ] Verify tests fail.
- [ ] Add `tagEmails` to `finding()` and `TagEmails` to CSV output.
- [ ] Enrich default Wiz-fetched endpoints with cached CloudAccount emails.
- [ ] Verify focused tests pass.

### Task 3: Documentation and validation

**Files:** `README.md`

- [ ] Document `tagEmails` / `TagEmails`.
- [ ] Run `python3 -m unittest test_upload_to_oss.py test_assess_attack_surface.py test_wiz_auth_poc.py`.
- [ ] Commit implementation.
