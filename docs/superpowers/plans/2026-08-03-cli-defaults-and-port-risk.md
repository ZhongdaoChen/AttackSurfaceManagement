# CLI Defaults and Port Risk Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the scanner default to the common full-scan settings and mark non-standard open ports as high risk.

**Architecture:** Keep all behavior in the existing single-file CLI scanner. Update argparse defaults and opt-out flags in `assess_attack_surface.py`, update the existing non-standard port checker risk level, and keep README/command examples aligned with the new defaults.

**Tech Stack:** Python 3 standard library, `argparse`, `unittest`, Markdown documentation.

## Global Constraints

- Do not add third-party runtime dependencies.
- Preserve existing JSONL/CSV output schemas.
- Keep `--timeout`, `--insecure-tls`, and `--enable-llm` accepted for backward-compatible command invocations.
- Add explicit opt-out flags `--secure-tls` and `--disable-llm`.
- Generated findings and `.env` must remain uncommitted.

---

### Task 1: CLI default settings

**Files:**
- Modify: `test_assess_attack_surface.py`
- Modify: `assess_attack_surface.py`

**Interfaces:**
- Consumes: `build_arg_parser() -> argparse.ArgumentParser`
- Produces: Parsed args where `timeout == 30`, `insecure_tls is True`, and `enable_llm is True` by default; `--secure-tls` sets `insecure_tls` false; `--disable-llm` sets `enable_llm` false.

- [ ] **Step 1: Write the failing parser default test**

Add to `test_assess_attack_surface.py` inside `AssessAttackSurfaceTests`:

```python
def test_arg_parser_defaults_to_full_scan_operational_settings(self):
    args = asm.build_arg_parser().parse_args([])

    self.assertEqual(args.timeout, 30)
    self.assertTrue(args.insecure_tls)
    self.assertTrue(args.enable_llm)
```

- [ ] **Step 2: Write the failing opt-out flag test**

Add to `test_assess_attack_surface.py` inside `AssessAttackSurfaceTests`:

```python
def test_arg_parser_allows_disabling_insecure_tls_and_llm(self):
    args = asm.build_arg_parser().parse_args(["--secure-tls", "--disable-llm"])

    self.assertFalse(args.insecure_tls)
    self.assertFalse(args.enable_llm)
```

- [ ] **Step 3: Run parser tests to verify they fail**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_arg_parser_defaults_to_full_scan_operational_settings test_assess_attack_surface.AssessAttackSurfaceTests.test_arg_parser_allows_disabling_insecure_tls_and_llm
```

Expected: FAIL because timeout is `10` and argparse does not recognize `--secure-tls` or `--disable-llm`.

- [ ] **Step 4: Implement minimal CLI default changes**

In `assess_attack_surface.py`, set:

```python
DEFAULT_TIMEOUT_SECONDS = 30
```

In `CheckContext`, set:

```python
insecure_tls: bool = True
llm_enabled: bool = True
```

In `build_arg_parser()`, configure paired flags:

```python
parser.set_defaults(insecure_tls=True, enable_llm=True)
parser.add_argument(
    "--insecure-tls",
    dest="insecure_tls",
    action="store_true",
    help="Disable TLS certificate verification for response-content triage. Enabled by default.",
)
parser.add_argument(
    "--secure-tls",
    dest="insecure_tls",
    action="store_false",
    help="Verify TLS certificates instead of using insecure content triage.",
)
parser.add_argument(
    "--enable-llm",
    dest="enable_llm",
    action="store_true",
    help="Enable OpenAI-compatible LLM content judgment. Enabled by default.",
)
parser.add_argument(
    "--disable-llm",
    dest="enable_llm",
    action="store_false",
    help="Disable OpenAI-compatible LLM content judgment.",
)
```

- [ ] **Step 5: Run parser tests to verify they pass**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_arg_parser_defaults_to_full_scan_operational_settings test_assess_attack_surface.AssessAttackSurfaceTests.test_arg_parser_allows_disabling_insecure_tls_and_llm
```

Expected: PASS.

---

### Task 2: Non-standard port risk level

**Files:**
- Modify: `test_assess_attack_surface.py`
- Modify: `assess_attack_surface.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: `NonStandardPortChecker().check(endpoint, context) -> list[dict[str, Any]]`
- Produces: `non_standard_open_port` findings with `risk_level == "high"`.

- [ ] **Step 1: Write the failing risk-level test**

Change `test_non_standard_open_port_returns_reduce_finding` in `test_assess_attack_surface.py`:

```python
self.assertEqual(findings[0]["risk_level"], "high")
```

- [ ] **Step 2: Run the focused test to verify it fails**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_non_standard_open_port_returns_reduce_finding
```

Expected: FAIL with `"medium" != "high"`.

- [ ] **Step 3: Implement minimal checker change**

Change the `finding(...)` call in `NonStandardPortChecker.check()` from:

```python
"medium",
```

to:

```python
"high",
```

- [ ] **Step 4: Update README risk description**

In `README.md`, move non-standard open ports from the `medium` description to the `high` description:

```markdown
- `high`：发现疑似敏感内容暴露，例如目录列表、secret-like value、错误栈、备份文件线索；或发现非标准开放端口。
- `medium`：需要人工 review，例如非登录页且无明确敏感信号的 HTTPS 页面、带信息泄露线索的 404。
```

- [ ] **Step 5: Run focused test to verify it passes**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_non_standard_open_port_returns_reduce_finding
```

Expected: PASS.

---

### Task 3: Documentation and regression alignment

**Files:**
- Modify: `README.md`
- Modify: `command.txt`
- Modify: `test_assess_attack_surface.py`

**Interfaces:**
- Consumes: CLI examples in `README.md` and `command.txt`.
- Produces: common commands that omit defaulted `--timeout 30`, `--insecure-tls`, and `--enable-llm`; tests that explicitly pass `llm_enabled=False` or `--disable-llm` when verifying local heuristic behavior.

- [ ] **Step 1: Update common commands**

In `README.md` and `command.txt`, remove these defaulted arguments from common scan commands:

```bash
--timeout 30
--insecure-tls
--enable-llm
```

Keep `--limit`, `--input`, `--output`, and `--csv-output` where already present.

- [ ] **Step 2: Document opt-out flags**

Add a short README note:

```markdown
`--timeout` 默认是 `30`，`--insecure-tls` 和 `--enable-llm` 默认开启。需要关闭时可使用 `--secure-tls` 或 `--disable-llm`。
```

- [ ] **Step 3: Align heuristic tests with LLM default**

For tests that directly assert local heuristic findings for HTTP 200 responses, pass `llm_enabled=False` in `asm.CheckContext(...)`. For main tests expecting heuristic output without an LLM client, pass `--disable-llm` in `asm.main([...])`.

- [ ] **Step 4: Run full test suite**

Run:

```bash
python3 -m unittest test_assess_attack_surface.py test_wiz_auth_poc.py
```

Expected: all tests pass.

- [ ] **Step 5: Commit and push**

Run:

```bash
git add assess_attack_surface.py test_assess_attack_surface.py README.md command.txt docs/superpowers/specs/2026-08-03-cli-defaults-design.md docs/superpowers/plans/2026-08-03-cli-defaults-and-port-risk.md
git commit -m "feat: default full scan settings" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
git push origin main
```

Expected: commit succeeds and push updates `origin/main`.
