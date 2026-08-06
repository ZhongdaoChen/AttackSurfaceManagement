# Cloud Account Tag Email Output Design

## Purpose

Add owner/contact email visibility to scan outputs by extracting email-like strings from Wiz CloudAccount/Subscription tags.

## Source

Application endpoint `tags` may be null. For endpoints like `https://52.80.67.201:9200`, the relevant tags are on the linked CloudAccount/Subscription entity:

- endpoint id: `62dfdb5d-813e-5c49-93da-07f5711dbf86`
- cloudAccount id: `31e7fa13-a9d0-59cb-9c5f-ae6bebce3e11`
- cloudAccount name: `adidas-linked-bam-pro-cn`

The CloudAccount GraphEntity contains tag data in:

- `properties.tags`
- `providerData.accountTags`

Example emails:

- `reema.jain@adidas.com`
- `AAD-AWS-ADIDAS-LINKED-BAM-PRO-CN-Admin@groups.adidas.com`

## Behavior

Before scanning, collect unique `cloudAccount.id` values from endpoints. Query each unique CloudAccount GraphEntity once, extract email-like strings from all tag keys and values, and attach the result to endpoints before findings are generated.

Output:

- JSONL finding field: `tagEmails`
- CSV column: `TagEmails`

If no email is found, output an empty list in JSONL and an empty string in CSV.

## Performance

Cache emails by `cloudAccount.id` to avoid querying the same CloudAccount once per endpoint.

## Scope

Only default Wiz-fetch mode is enriched. `--input` JSONL mode uses whatever `tagEmails` data is already present in the input and does not call Wiz for enrichment.

## Testing

Add tests for:

- Extracting emails from nested CloudAccount tag metadata.
- Enriching multiple endpoints with cached CloudAccount emails.
- JSONL finding includes `tagEmails`.
- CSV includes `TagEmails`.
