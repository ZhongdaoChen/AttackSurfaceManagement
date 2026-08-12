# RDS Streaming Writer Design

## Purpose

Persist scan findings into PostgreSQL RDS while the scanner writes JSONL and CSV outputs.

## Behavior

When RDS environment variables are configured, each finding should be inserted into PostgreSQL in the same loop that writes JSONL and CSV:

- `RDS_HOST`
- `RDS_PORT`
- `RDS_DB`
- `RDS_USER`
- `RDS_PASSWORD`
- `RDS_SSLMODE` optional, default `prefer`

If these variables are absent, local scans should continue without database writes.

If database writing is enabled and an insert fails, the scan should fail. This avoids a misleading state where output files exist but database rows are missing.

## Tables

Use existing `schema.sql` tables:

- `asm_scans`
- `asm_findings`

`asm_findings.raw` stores the full JSONL finding object.

## whitelisted

`asm_findings.whitelisted` should be true when the finding is low because it matched a low-risk subscription/account exception. The first implementation can derive this from:

- `details.subscription` exists and matches `LOW_RISK_SUBSCRIPTIONS`

Otherwise `whitelisted` is false.

## Integration

Add an isolated `rds_writer.py` module. `assess_attack_surface.py` opens the writer after resolving output paths and closes it at the end.

The scanner writes each finding to:

1. JSONL
2. CSV, if enabled
3. RDS, if enabled

## Testing

Use fake connection/cursor objects in unit tests. Local tests must not require RDS network access.
