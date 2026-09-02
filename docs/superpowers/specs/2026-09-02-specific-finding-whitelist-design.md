# Specific Finding Whitelist Design

## Purpose

Support whitelisting one specific ASM finding without whitelisting the whole cloud account or every finding on the same endpoint. A finding-level whitelist must remain effective across future scans as long as the scan produces the same stable finding identity.

## Current behavior

The project currently has two whitelist mechanisms:

- Scanner account-level downgrades: `LOW_RISK_SUBSCRIPTIONS` marks findings low risk when `details.subscription` belongs to a configured low-risk account or subscription set.
- Dashboard endpoint rules: `asm_whitelist_rules` stores `endpoint_name + port` rules. `RdsFindingWriter.write()` checks active rules while writing future scan rows. `asm_dashboard.db.create_whitelist_rule()` also backfills matching current and historical findings.

These mechanisms are too broad for the new requirement. Account-level rules affect all findings in an account, and endpoint rules can affect multiple checks on the same endpoint and port.

## Design

Add a separate finding-level whitelist model instead of extending account-level behavior.

Create a new table named `asm_finding_whitelist_rules` with:

- `id`
- `finding_key`
- readable finding snapshot fields: `endpoint_name`, `host`, `port`, `check_id`, `cloud_account_name`
- `reason`
- `operator_name`
- `active`
- `created_at`
- `deactivated_at`
- `deactivated_by`
- `deactivation_reason`

The `finding_key` is the existing stable key computed by `rds_writer.finding_key()`:

```text
sha256(endpoint_id, check_id, host, port)
```

This keeps the match narrow enough to avoid affecting other findings in the same account, other checks on the same endpoint, or other ports on the same host.

## Write path

`RdsFindingWriter.write()` already computes `params["finding_key"]` before inserting rows. Add a finding-rule lookup alongside the existing endpoint-rule lookup:

```text
whitelisted = account whitelist OR endpoint/port whitelist OR finding_key whitelist
```

When an active `asm_finding_whitelist_rules.finding_key` matches the computed key, the writer marks both the historical row and current row as `whitelisted=true`. Future scans therefore keep suppressing the same specific finding without requiring a cloud-account whitelist.

## Dashboard creation flow

Current Status row expansion should show clearly separated actions:

- `Whitelist this finding`
- `Whitelist endpoint + port`

`Whitelist this finding` opens a dedicated dialog. The dialog should display the finding identity fields and explain that the rule applies only to this finding key:

- It does not whitelist the cloud account.
- It does not whitelist other findings on the same endpoint.
- It does not whitelist other checks, hosts, or ports.

On submit, dashboard DB code inserts an active `asm_finding_whitelist_rules` row using the selected current finding's `finding_key` and snapshot fields. It then immediately updates only that current row:

```text
asm_current_findings.finding_key = selected finding_key
```

The update sets `whitelisted=true`, `resolved_at=now()`, and `resolved_scan_id` to the latest scan so the row disappears from Current Status and counts as mitigated.

Because `asm_findings` does not currently store `finding_key`, historical backfill should match the selected current row by the same identity inputs:

```text
endpoint_id + check_id + host + port
```

This avoids changing unrelated findings in the same cloud account or on the same endpoint.

## Rules page

The whitelist management page should distinguish rule types explicitly. Use two sections or tabs:

- `Finding Whitelist Rules`
- `Endpoint/Port Whitelist Rules`

Finding rules should show `finding_key`, endpoint, host, port, check ID, cloud account, active state, reason, operator, and created date. Endpoint/port rules keep their current display and behavior.

Each rule type should have its own deactivate form. Deactivating a finding-level rule only sets the finding rule inactive and records deactivation metadata.

## Lifecycle and metrics

Deactivation should follow the existing whitelist semantics: it only affects future scans and does not bulk-revert historical `whitelisted=true` rows.

Exposure Trend must include finding-level whitelist effective times in the same way it includes endpoint/port whitelist effective times. Otherwise, `Cumulative Mitigated` would miss findings suppressed by the new rule type.

High-risk Teams notifications must continue to exclude finding-level whitelisted rows because they are written as `whitelisted=true` before `finalize()` sends notifications.

## Error handling

Dashboard creation should validate:

- `finding_key` is present.
- `reason` is non-empty.
- `operator_name` is non-empty.

Invalid input should raise or surface explicit errors using the existing dashboard error display pattern. The implementation should not silently skip rule creation or partial backfill.

## Testing

Add focused tests for:

- Schema definition of `asm_finding_whitelist_rules` and its active lookup index.
- RDS writer marking a future scan row whitelisted when the computed `finding_key` matches an active finding rule.
- RDS writer not marking a different finding in the same cloud account as whitelisted.
- Dashboard DB creation inserting a finding rule, updating only the selected current finding, and backfilling only historical rows with the same identity inputs.
- Dashboard UI exposing a separate `Whitelist this finding` entry distinct from `Whitelist endpoint + port`.
- Finding rule deactivation updating only rule metadata, without reverting historical rows.
- Exposure Trend SQL including finding-level whitelist effective times.
