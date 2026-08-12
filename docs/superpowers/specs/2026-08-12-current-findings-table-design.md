# Current Findings Table Design

## Purpose

`asm_findings` currently stores scan history: each scan writes its own findings, so the same finding can appear once per scan. Keep that behavior for auditability and trend analysis, and add a separate current-state table for deduplicated “latest status” queries.

## Data Model

Keep the existing tables unchanged:

- `asm_scans`: one row per scan.
- `asm_findings`: immutable scan result history, linked to `asm_scans.scan_id`.

Add `asm_current_findings` for the latest lifecycle state of each logical finding. It uses a stable `finding_key` as the unique identifier, derived from the same identity fields that currently deduplicate within a scan:

- `endpoint_id`
- `check_id`
- `host`
- `port`

Null identity fields are normalized to empty strings, except `port`, which uses `-1`, matching the existing unique index semantics on `asm_findings`.

Recommended fields:

- `finding_key TEXT PRIMARY KEY`
- Latest finding identity and display fields: `endpoint_id`, `endpoint_name`, `wiz_link`, `host`, `port`, `cloud_platform`, `cloud_account_name`, `tag_emails`, `exposure_level`, `check_id`
- Latest assessment fields: `risk_level`, `whitelisted`, `http_status`, `http_response`, `llm_opinion`, `evidence`, `recommendation`, `details`, `raw`
- Lifecycle fields: `first_seen_scan_id`, `first_seen_at`, `last_seen_scan_id`, `last_seen_at`, `seen_count`, `resolved_at`, `resolved_scan_id`

## Write Flow

`RdsFindingWriter.write()` continues inserting into `asm_findings` exactly as it does today. After that insert, it computes `finding_key` and upserts `asm_current_findings`.

For a new key, the current table insert sets both first-seen and last-seen fields to the current scan. For an existing key, the upsert refreshes the latest finding fields, updates `last_seen_scan_id` and `last_seen_at`, increments `seen_count`, and clears `resolved_at` and `resolved_scan_id` because the finding is active again.

At the end of each scan, the writer finalizes current-state records by marking entries not seen in the current `scan_id` as resolved. Finalization sets `resolved_at` and `resolved_scan_id` for rows whose `last_seen_scan_id` is not the current scan and whose `resolved_at` is still null.

## Query Behavior

Historical reporting continues to query `asm_findings`.

Current active findings query `asm_current_findings WHERE resolved_at IS NULL`.

Recently resolved findings query `asm_current_findings WHERE resolved_at IS NOT NULL`, optionally ordered by `resolved_at DESC`.

## Error Handling

Historical insert, current-state upsert, and scan finalization should use the same database connection and surface errors instead of swallowing them. If the current-state write fails, the scan should fail visibly rather than silently leaving `asm_findings` and `asm_current_findings` inconsistent.

RDS-disabled behavior remains unchanged: when RDS configuration is absent, no writer is opened and no database writes occur.

## Testing

Add RDS writer unit tests for:

- deterministic `finding_key` generation with normalized null fields
- `asm_findings` historical insert still occurring
- `asm_current_findings` insert/upsert parameters
- clearing resolved fields when a finding reappears
- finalization SQL marking findings absent from the current scan as resolved
- preserving existing same-scan duplicate handling through `ON CONFLICT DO NOTHING`

No historical data migration is required for the first implementation. Current-state lifecycle tracking starts with the first scan after this change is deployed.
