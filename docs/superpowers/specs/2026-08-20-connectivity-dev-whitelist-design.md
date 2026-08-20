# Connectivity-Dev Whitelist Design

## Purpose

Add `Connectivity-Dev Development` and `014826645533` to the low-risk subscription/account whitelist used by non-standard port assessment.

## Current behavior

`assess_attack_surface.py` stores low-risk account identifiers in `LOW_RISK_SUBSCRIPTIONS`.
`subscription_value()` extracts the first available subscription/account value from endpoint fields or `cloudAccount`.
`is_low_risk_subscription()` lowercases the extracted value before checking membership in `LOW_RISK_SUBSCRIPTIONS`.

When a non-standard open port cannot be classified by HTTP content probing, the fallback finding is `low` only if the endpoint subscription/account matches the whitelist. Otherwise it is `high`.

## Required change

Add these normalized entries to `LOW_RISK_SUBSCRIPTIONS`:

- `connectivity-dev development`
- `014826645533`

The display value `Connectivity-Dev Development` should keep working through the existing lowercase normalization. The numeric account ID should match exactly as a string, consistent with existing account ID whitelist entries.

## Testing

Update `test_assess_attack_surface.py` with focused coverage for both requested identifiers:

- A `cloudAccount.name` value of `Connectivity-Dev Development` lowers a fallback non-standard open port finding to `low`.
- An `accountId` value of `014826645533` lowers a fallback non-standard open port finding to `low`.
- The finding details preserve the original extracted subscription/account value.

No schema, RDS writer, dashboard, or endpoint+port whitelist changes are required.
