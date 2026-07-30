# Wiz Endpoint Link CSV Design

## Purpose

The final CSV should include a clickable Wiz console link for each application endpoint finding. Analysts should be able to open the CSV, click the link, and land on the corresponding Wiz application endpoint details page.

## Approved approach

Use the current Wiz tenant URL format directly in the scanner. The link format is:

```text
https://app.wiz.io/p/secengcnaccounts/inventory/application-endpoints#%7E%28entity%7E%28%7E%27{endpoint_id}*2cENDPOINT%29%29
```

`{endpoint_id}` is the Wiz application endpoint `id` already present in the endpoint payload and copied into each finding as `endpoint_id`.

## CSV output

Add a new CSV column named `Wiz链接`. For each finding:

- If `endpoint_id` is present, `Wiz链接` contains the Wiz console URL for that endpoint.
- If `endpoint_id` is missing or empty, `Wiz链接` is empty.
- Existing CSV columns and meanings stay unchanged.
- JSONL output keeps its existing fields; no new JSON-only behavior is required.

## Components

- Add `wiz_endpoint_url(endpoint_id)` in `assess_attack_surface.py`.
- Update `CSV_FIELDNAMES` to include `Wiz链接`.
- Update `csv_row_for_finding()` to populate `Wiz链接` from `finding_item["endpoint_id"]`.

## Testing

Add unit coverage for:

- CSV rows include a correct `Wiz链接` when `endpoint_id` is present.
- CSV rows leave `Wiz链接` empty when `endpoint_id` is absent.
- The existing `main()` flow that fetches endpoints from Wiz writes the link into CSV output.

Run the existing unit suite after implementation to verify CSV changes do not break current behavior.
