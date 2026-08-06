# Subscription Non-Standard Port Risk Design

## Purpose

Downgrade selected non-standard open port findings from `high` to `low` when the endpoint belongs to known lower-priority subscriptions/accounts.

## Behavior

`NonStandardPortChecker` should keep its current default behavior:

- Endpoint `portStatus` must be `OPEN`.
- Ports `80` and `443` are ignored by this checker.
- Other open ports produce `check_id = "non_standard_open_port"`.
- Default risk remains `high`.

Add a subscription/account exception:

- If endpoint subscription/account metadata matches `FDP`, mark the finding `low`.
- If endpoint subscription/account metadata matches `197575089658`, mark the finding `low`.
- Matching should be case-insensitive for text values such as `FDP`.

The first regression example is:

- `host = "68.79.15.14"`
- `port = 9095`
- subscription metadata = `FDP`
- expected risk = `low`

## Metadata source

Avoid scraping Wiz UI HTML. The scanner should read subscription/account metadata from endpoint data supplied by Wiz/API/input JSONL. The implementation should support common field names so it can work with either direct GraphQL fields or enriched input:

- `subscription`
- `Subscription`
- `subscriptionName`
- `subscriptionId`
- `accountId`
- `cloudAccountId`

If no supported metadata field is present, the checker should keep the default `high` result.

## Output details

When downgraded, the finding should include the matched subscription/account value in `details`, for example:

```json
{"subscription": "FDP"}
```

The evidence or recommendation should mention that the port is still non-standard but was downgraded because of the subscription/account exception.

## Testing

Add tests for:

- `68.79.15.14:9095` with `subscription = "FDP"` returns low.
- `197575089658` in a supported account/subscription field returns low.
- A normal non-standard open port without matching metadata remains high.
