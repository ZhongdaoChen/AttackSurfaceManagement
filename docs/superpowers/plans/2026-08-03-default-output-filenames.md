# Default Output Filenames Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `assess_attack_surface.py` create timestamped JSONL and CSV findings files when `--output` is omitted.

**Architecture:** Keep the change inside the existing scanner CLI. Add small output path resolution helpers in `assess_attack_surface.py`, keep explicit `--output`/`--csv-output` behavior unchanged, and update README examples to document the no-output default.

**Tech Stack:** Python 3 standard library, `argparse`, `datetime`, `unittest`, Markdown.

## Global Constraints

- Timestamped filenames apply only when `--output` is omitted.
- Default filenames use `YYYYMMDD-HHMMSS-asm-findings.jsonl` and `YYYYMMDD-HHMMSS-asm-findings.csv`.
- `--output -` continues to write JSONL to stdout.
- Explicit `--output` does not imply CSV unless `--csv-output` is provided.
- JSONL/CSV schemas stay unchanged.

---

### Task 1: Resolve timestamped output paths

**Files:**
- Modify: `test_assess_attack_surface.py`
- Modify: `assess_attack_surface.py`

**Interfaces:**
- Consumes: `build_arg_parser() -> argparse.ArgumentParser`
- Produces: `default_output_paths(now: datetime.datetime) -> tuple[str, str]` and `resolve_output_paths(args: argparse.Namespace, now: datetime.datetime | None = None) -> tuple[str, str | None]`

- [ ] **Step 1: Write failing helper tests**

Add to `test_assess_attack_surface.py`:

```python
def test_default_output_paths_use_timestamp_prefix(self):
    now = asm.datetime.datetime(2026, 8, 3, 14, 29, 9)

    json_path, csv_path = asm.default_output_paths(now)

    self.assertEqual(json_path, "20260803-142909-asm-findings.jsonl")
    self.assertEqual(csv_path, "20260803-142909-asm-findings.csv")

def test_resolve_output_paths_creates_jsonl_and_csv_when_output_omitted(self):
    args = asm.build_arg_parser().parse_args([])
    now = asm.datetime.datetime(2026, 8, 3, 14, 29, 9)

    json_path, csv_path = asm.resolve_output_paths(args, now)

    self.assertEqual(json_path, "20260803-142909-asm-findings.jsonl")
    self.assertEqual(csv_path, "20260803-142909-asm-findings.csv")

def test_resolve_output_paths_preserves_explicit_output_behavior(self):
    args = asm.build_arg_parser().parse_args(["--output", "-", "--csv-output", "custom.csv"])

    json_path, csv_path = asm.resolve_output_paths(args, asm.datetime.datetime(2026, 8, 3, 14, 29, 9))

    self.assertEqual(json_path, "-")
    self.assertEqual(csv_path, "custom.csv")
```

- [ ] **Step 2: Run helper tests to verify they fail**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_default_output_paths_use_timestamp_prefix test_assess_attack_surface.AssessAttackSurfaceTests.test_resolve_output_paths_creates_jsonl_and_csv_when_output_omitted test_assess_attack_surface.AssessAttackSurfaceTests.test_resolve_output_paths_preserves_explicit_output_behavior
```

Expected: FAIL because the helper functions do not exist and parser default still uses `"-"`.

- [ ] **Step 3: Implement minimal helpers**

In `assess_attack_surface.py`, add:

```python
import datetime
```

Change parser output default to:

```python
parser.add_argument("--output", help="Output findings JSONL file. If omitted, timestamped JSONL and CSV files are created; use '-' for stdout.")
```

Add helpers before `main()`:

```python
def default_output_paths(now: datetime.datetime) -> tuple[str, str]:
    prefix = now.strftime("%Y%m%d-%H%M%S-asm-findings")
    return f"{prefix}.jsonl", f"{prefix}.csv"


def resolve_output_paths(args: argparse.Namespace, now: datetime.datetime | None = None) -> tuple[str, str | None]:
    if args.output is None:
        return default_output_paths(now or datetime.datetime.now())
    return args.output, args.csv_output
```

- [ ] **Step 4: Run helper tests to verify they pass**

Run the same three helper tests. Expected: PASS.

---

### Task 2: Wire resolved paths into main

**Files:**
- Modify: `test_assess_attack_surface.py`
- Modify: `assess_attack_surface.py`

**Interfaces:**
- Consumes: `resolve_output_paths(args, now=None) -> tuple[str, str | None]`
- Produces: `main(argv)` that creates both timestamped files when `--output` is omitted.

- [ ] **Step 1: Write failing main integration test**

Add to `test_assess_attack_surface.py`:

```python
def test_main_without_output_creates_timestamped_jsonl_and_csv_files(self):
    with tempfile.TemporaryDirectory() as temp_dir:
        input_path = os.path.join(temp_dir, "input.jsonl")
        with open(input_path, "w", encoding="utf-8") as input_file:
            input_file.write(
                json.dumps(
                    {
                        "id": "endpoint-1",
                        "name": "https://app.example.com:443",
                        "host": "app.example.com",
                        "port": 443,
                        "protocols": ["HTTPS"],
                        "cloudPlatform": "AWS",
                    }
                )
                + "\n"
            )

        def fetcher(request, timeout, context=None):
            return asm.HttpResponse(
                url=request.full_url,
                status=200,
                headers={"Content-Type": "text/html"},
                body=b"<html><title>Welcome</title><p>Public page</p></html>",
            )

        real_datetime = asm.datetime.datetime

        class FixedDateTime(real_datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(2026, 8, 3, 14, 29, 9, tzinfo=tz)

        current_dir = os.getcwd()
        with (
            patch.object(asm, "fetch_url", fetcher),
            patch.object(asm.datetime, "datetime", FixedDateTime),
        ):
            os.chdir(temp_dir)
            try:
                exit_code = asm.main(["--input", input_path, "--disable-llm"])
            finally:
                os.chdir(current_dir)

        json_path = os.path.join(temp_dir, "20260803-142909-asm-findings.jsonl")
        csv_path = os.path.join(temp_dir, "20260803-142909-asm-findings.csv")

        self.assertEqual(exit_code, 0)
        self.assertTrue(os.path.exists(json_path))
        self.assertTrue(os.path.exists(csv_path))
```

- [ ] **Step 2: Run integration test to verify it fails**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_main_without_output_creates_timestamped_jsonl_and_csv_files
```

Expected: FAIL because `main()` still writes to stdout when output is omitted.

- [ ] **Step 3: Wire resolved paths into main**

In `main()`, replace direct `args.output`/`args.csv_output` file selection with:

```python
output_path, csv_output_path = resolve_output_paths(args)
output = sys.stdout if output_path == "-" else open(output_path, "w", encoding="utf-8")
csv_output = open(csv_output_path, "w", encoding="utf-8", newline="") if csv_output_path else None
```

- [ ] **Step 4: Run integration test to verify it passes**

Run the focused integration test. Expected: PASS.

---

### Task 3: Documentation and full verification

**Files:**
- Modify: `README.md`
- Modify: `command.txt`
- Test: `test_assess_attack_surface.py`
- Test: `test_wiz_auth_poc.py`

**Interfaces:**
- Consumes: scanner CLI examples.
- Produces: docs showing no-output default and explicit deterministic output examples.

- [ ] **Step 1: Update command example**

Change `command.txt` to:

```bash
python3 assess_attack_surface.py
```

- [ ] **Step 2: Update README common commands**

Document that this command writes timestamped JSONL/CSV outputs:

```bash
python3 assess_attack_surface.py
```

Keep explicit output examples for limit/input scans if useful.

- [ ] **Step 3: Run full tests**

Run:

```bash
python3 -m unittest test_assess_attack_surface.py test_wiz_auth_poc.py
```

Expected: all tests pass.

- [ ] **Step 4: Commit changes**

Run:

```bash
git add assess_attack_surface.py test_assess_attack_surface.py README.md command.txt docs/superpowers/plans/2026-08-03-default-output-filenames.md
git commit -m "feat: add timestamped default outputs" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```
