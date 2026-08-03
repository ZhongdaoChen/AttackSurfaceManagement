# Default Output Filenames Design

## Purpose

When the scanner is run without `--output`, generate the same two artifact types used by the current explicit full-scan command: JSONL findings and CSV findings. Both files should use a timestamp prefix so repeated runs do not overwrite prior results.

## Selected behavior

Use timestamped filenames only when `--output` is omitted:

- JSONL: `YYYYMMDD-HHMMSS-asm-findings.jsonl`
- CSV: `YYYYMMDD-HHMMSS-asm-findings.csv`

If `--output` is explicitly provided, preserve current behavior:

- `--output path.jsonl` writes JSONL to that path.
- `--output -` writes JSONL to stdout.
- CSV is written only when `--csv-output path.csv` is explicitly provided.

This keeps existing scripted invocations stable while making the no-argument output path useful for ECS/manual operation.

## CLI and data flow

`argparse` should distinguish between an omitted `--output` and an explicit value. The main flow should resolve output paths after parsing:

- If `args.output is None`, compute one timestamp prefix and assign both default paths.
- If `args.output` has any value, use it unchanged and do not infer CSV unless `args.csv_output` is set.

The timestamp must be created once per run so JSONL and CSV filenames share the same prefix.

## Documentation

Update README examples to show that a simple scan can be run without output arguments and will create timestamped JSONL/CSV files. Keep examples with explicit paths where useful for deterministic file names.

## Testing

Add unit coverage for:

- Parser default for `--output` is distinguishable from explicit stdout.
- Running `main()` without `--output` creates both timestamped files.
- Existing explicit `--output` plus `--csv-output` behavior still works.
