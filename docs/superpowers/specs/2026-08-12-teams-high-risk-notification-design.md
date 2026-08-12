# Teams High Risk Notification Design

## Purpose

Send a Microsoft Teams notification when a completed scan finds High risk endpoints that did not exist in previous scans. The notification uses the confirmed Teams Workflows webhook format: a top-level Adaptive Card JSON object.

## Trigger

After a successful scan writes findings to RDS and finalizes current findings, query `asm_current_findings` for active High risk findings whose `first_seen_scan_id` equals the current scan id:

```sql
SELECT endpoint_name, wiz_link, host, port, cloud_account_name, check_id,
       evidence, recommendation, first_seen_scan_id, first_seen_at
FROM asm_current_findings
WHERE first_seen_scan_id = %(scan_id)s
  AND risk_level = 'high'
  AND resolved_at IS NULL
ORDER BY first_seen_at ASC, endpoint_name ASC, host ASC, port ASC
```

If this query returns zero rows, no Teams message is sent.

## Configuration

Use `TEAMS_WEBHOOK_URL` from the existing `.env` loading flow. If the variable is absent or empty, skip Teams notification without failing the scan.

The scan must still complete and write local/CSV/RDS output even when Teams notification is not configured.

## Message Body

The payload is an Adaptive Card 1.4 object posted directly to `TEAMS_WEBHOOK_URL`:

```json
{
  "type": "AdaptiveCard",
  "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
  "version": "1.4",
  "body": [
    {
      "type": "TextBlock",
      "text": "ASM 新增 High Risk 告警",
      "weight": "Bolder",
      "size": "Large",
      "color": "Attention"
    },
    {
      "type": "TextBlock",
      "text": "本次扫描发现 3 个新增 High Risk endpoint。",
      "wrap": true
    },
    {
      "type": "FactSet",
      "facts": [
        {"title": "Scan ID", "value": "20260812-112000-asm-findings"},
        {"title": "First seen", "value": "2026-08-12T11:20:00+08:00"},
        {"title": "Total", "value": "3"}
      ]
    },
    {
      "type": "TextBlock",
      "text": "1. https://app.example.com:9200",
      "weight": "Bolder",
      "wrap": true,
      "separator": true
    },
    {
      "type": "FactSet",
      "facts": [
        {"title": "Host", "value": "app.example.com"},
        {"title": "Port", "value": "9200"},
        {"title": "CloudAccount", "value": "account-name"},
        {"title": "Check", "value": "non_standard_open_port"},
        {"title": "Evidence", "value": "Open non-standard internet-facing port 9200."},
        {"title": "Recommendation", "value": "Confirm business need; close or restrict the port."}
      ]
    }
  ],
  "actions": [
    {
      "type": "Action.OpenUrl",
      "title": "Open first finding in Wiz",
      "url": "https://app.wiz.io/..."
    }
  ]
}
```

## Limits and Formatting

- Include at most the first 10 findings in the card.
- If more than 10 new High risk findings exist, the summary text says only the first 10 are shown.
- Truncate `Evidence` and `Recommendation` values to 300 characters each.
- Use `endpoint_name` as the finding heading when present; otherwise use `host:port`; otherwise use the endpoint id if available.
- Include the `Open first finding in Wiz` action only when the first displayed finding has a non-empty `wiz_link`.

## Error Handling

Teams notification failures must not roll back scan or RDS writes. If the webhook request fails, print a clear error to stderr including the HTTP status or exception type. The cron log will capture the failure.

Do not print `TEAMS_WEBHOOK_URL` because it is a secret-bearing URL.

## Testing

Add unit tests for:

- Building a valid top-level Adaptive Card payload.
- Limiting displayed findings to 10 and noting omitted findings.
- Truncating long evidence and recommendation strings.
- Skipping webhook sends when `TEAMS_WEBHOOK_URL` is missing.
- Sending the webhook only when new High risk findings exist.
- Ensuring webhook failure is logged but does not fail the scan.
