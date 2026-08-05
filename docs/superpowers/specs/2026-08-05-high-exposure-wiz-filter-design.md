# High Exposure Wiz Filter Design

## Purpose

Limit Wiz application endpoint ingestion to endpoints whose Wiz `exposureLevel` is `HIGH`.

## Behavior

The Wiz GraphQL variables for `applicationEndpoints` should include both:

```python
{"project": [WIZ_PROJECT_ID], "exposureLevel": ["HIGH"]}
```

This filter applies during Wiz data retrieval before scanner checks run. Input JSONL mode remains unchanged because it scans whatever the input file contains.

## Documentation

Update README scope notes to state that default Wiz fetching now filters by project and `exposureLevel=HIGH`.

## Testing

Update Wiz API unit tests so pagination and project filter tests assert the new `exposureLevel` filter is present on every GraphQL request.
