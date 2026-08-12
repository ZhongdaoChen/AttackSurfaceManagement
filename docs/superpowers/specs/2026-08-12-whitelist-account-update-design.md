# Whitelist Account Update Design

## Purpose

Update the low-risk subscription/account whitelist used by non-standard port assessment. The change removes `odp-china-account` from the whitelist and adds the requested account names that are not already present.

## Current Behavior

`assess_attack_surface.py` stores whitelisted account identifiers in `LOW_RISK_SUBSCRIPTIONS`. `subscription_value()` strips leading and trailing whitespace from endpoint subscription/account values, and `is_low_risk_subscription()` compares the stripped value in lowercase against the whitelist set.

The following requested entries already exist and do not need duplicate additions:

- `adidas-linked-bam-int-cn`
- `adidas-linked-bam-pro-cn`
- `adidas-linked-bam-dev-cn`

## Required Changes

Remove this entry:

- `odp-china-account`

Add these normalized lowercase entries:

- `adidas-linked-tibcochinahub-prod-cn`
- `adidas-linked-tibcochinahub-uat-cn`
- `adidas-linked-tibcochinahub-sit-cn`
- `mobileprintjob production`
- `artifactory-china production`
- `harbor production`
- `harbor staging`
- `adidas-linked-harbor-prod-cn`
- `adidas-linked-harbor-stg-cn`
- `foundation-account`
- `wizcnapp-production`
- `wizcnapp-development`
- `wiz cnapp development`

`Wiz CNAPP Development ` and `Wiz CNAPP Development` intentionally map to the same normalized whitelist entry: `wiz cnapp development`.

## Testing

Update `test_assess_attack_surface.py` to verify:

- `odp-china-account` no longer lowers sensitive non-standard port findings to `low`.
- Every newly added account lowers a sensitive non-standard port fallback finding to `low`.
- Mixed-case and trailing-space input for `Wiz CNAPP Development ` still matches because the existing normalization trims whitespace and lowercases values.

No schema or RDS writer behavior changes are required.
