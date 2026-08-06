# ECS Role OSS Upload Script Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a standalone `upload_to_oss.py` script that uploads files to OSS using ECS RAM role temporary credentials.

**Architecture:** Keep the uploader isolated from the scanner. Use Python standard library to load `.env`, fetch ECS role credentials from metadata, build OSS object keys, sign OSS V4 `PUT` requests, and upload one or more local files.

**Tech Stack:** Python 3 standard library: `argparse`, `datetime`, `hashlib`, `hmac`, `json`, `os`, `pathlib`, `urllib.request`, `unittest`.

## Global Constraints

- Do not modify scanner runtime flow.
- Do not require long-lived OSS AccessKey/Secret.
- Do not add dependencies.
- Read `OSS_ENDPOINT`, `OSS_BUCKET`, optional `OSS_PREFIX`, optional `OSS_ROLE_NAME`.
- Default `OSS_PREFIX` is `asm-findings/`.
- Use ECS metadata service for temporary credentials.

---

### Task 1: Configuration and metadata credentials

**Files:**
- Create: `upload_to_oss.py`
- Create: `test_upload_to_oss.py`

**Interfaces:**
- Produces: `load_dotenv(path: str | None = None) -> None`
- Produces: `discover_role_name(fetcher: Callable[[str], bytes]) -> str`
- Produces: `fetch_role_credentials(role_name: str | None = None, fetcher: Callable[[str], bytes] | None = None) -> dict[str, str]`
- Produces: `object_key_for_file(path: str | Path, prefix: str) -> str`

- [ ] **Step 1: Write failing tests**

Create tests for `.env` loading, role discovery, credential fetching, and object key generation.

- [ ] **Step 2: Run tests for RED**

Run:

```bash
python3 -m unittest test_upload_to_oss.py
```

Expected: FAIL because module does not exist.

- [ ] **Step 3: Implement config and metadata helpers**

Create `upload_to_oss.py` with standard-library helpers for dotenv parsing, metadata GET, JSON credential parsing, and object key generation.

- [ ] **Step 4: Run tests for GREEN**

Run `python3 -m unittest test_upload_to_oss.py`. Expected: PASS.

---

### Task 2: OSS V4 signed PUT upload

**Files:**
- Modify: `upload_to_oss.py`
- Modify: `test_upload_to_oss.py`

**Interfaces:**
- Produces: `upload_file(path: str | Path, endpoint: str, bucket: str, credentials: dict[str, str], prefix: str = "asm-findings/", opener: Callable[[urllib.request.Request], Any] | None = None) -> str`

- [ ] **Step 1: Write failing upload request test**

Test that `upload_file()` builds a PUT request to `https://bucket.endpoint/prefix/basename`, includes `x-oss-security-token`, uses the file bytes as body, and returns the object key.

- [ ] **Step 2: Run tests for RED**

Run `python3 -m unittest test_upload_to_oss.py`. Expected: FAIL because upload logic is absent.

- [ ] **Step 3: Implement OSS V4 signing and PUT**

Implement enough OSS V4 signing for `PUT` object:

- SHA256 payload hash.
- Canonical headers including host, date, content hash, token.
- Authorization header.
- Standard-library `urllib.request.Request`.

- [ ] **Step 4: Run tests for GREEN**

Run `python3 -m unittest test_upload_to_oss.py`. Expected: PASS.

---

### Task 3: CLI, docs, and verification

**Files:**
- Modify: `upload_to_oss.py`
- Modify: `README.md`
- Test: `test_upload_to_oss.py`

**Interfaces:**
- Produces CLI: `python3 upload_to_oss.py FILE [FILE ...]`

- [ ] **Step 1: Add CLI main**

Parse positional files and optional `--prefix`, load `.env`, read env config, fetch role credentials, upload all files, and print uploaded `oss://bucket/key` lines.

- [ ] **Step 2: Update README**

Document `.env` OSS config and command:

```bash
python3 upload_to_oss.py 20260806-140118-asm-findings.jsonl 20260806-140118-asm-findings.csv
```

- [ ] **Step 3: Run full tests**

Run:

```bash
python3 -m unittest test_upload_to_oss.py test_assess_attack_surface.py test_wiz_auth_poc.py
```

Expected: all tests pass.

- [ ] **Step 4: Commit implementation**

Run:

```bash
git add upload_to_oss.py test_upload_to_oss.py README.md docs/superpowers/plans/2026-08-06-ecs-role-oss-upload-script.md
git commit -m "feat: add ECS role OSS uploader" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```
