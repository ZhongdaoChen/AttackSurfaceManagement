# CLI Defaults Design

## Purpose

Make the scanner's common full-scan behavior the default: 30-second HTTP timeout, unverified TLS content triage enabled, and LLM content assessment enabled.

## Selected approach

Use defaults that match the current operational command and add explicit opt-out flags:

- `--timeout` defaults to `30`.
- `--insecure-tls` is enabled by default.
- `--enable-llm` is enabled by default.
- Add `--secure-tls` to restore certificate verification for a run.
- Add `--disable-llm` to run without LLM assessment.

This keeps the short command aligned with the current full-scan workflow while preserving a safe way to disable either behavior for troubleshooting or constrained environments.

## CLI behavior

The default full scan becomes:

```bash
python3 assess_attack_surface.py \
  --output asm-findings-full-latest.jsonl \
  --csv-output asm-findings-full-latest.csv
```

Users can override the defaults:

```bash
python3 assess_attack_surface.py \
  --output asm-findings-full-latest.jsonl \
  --csv-output asm-findings-full-latest.csv \
  --timeout 10 \
  --secure-tls \
  --disable-llm
```

## Code changes

Update `assess_attack_surface.py` only:

- Change `DEFAULT_TIMEOUT_SECONDS` from `10` to `30`.
- Change `CheckContext` defaults for `insecure_tls` and `llm_enabled` to `True`.
- Replace single-direction argparse flags with paired boolean controls:
  - `--insecure-tls` and `--secure-tls`.
  - `--enable-llm` and `--disable-llm`.
- Keep existing runtime behavior after argument parsing: `CheckContext` receives the final parsed booleans, and `default_checkers()` includes the LLM checker when LLM is enabled.

## Documentation changes

Update `README.md` and `command.txt` so common commands omit defaulted flags and document the new opt-out flags. Keep the security note that insecure TLS is for content triage, not a production control.

## Testing

Update unit tests to cover:

- Parser defaults: timeout 30, insecure TLS enabled, LLM enabled.
- Opt-out flags: `--secure-tls` disables insecure TLS, `--disable-llm` disables LLM.
- Existing scanner, CSV, redirect, and Wiz API behavior remains covered by the full unittest suite.
