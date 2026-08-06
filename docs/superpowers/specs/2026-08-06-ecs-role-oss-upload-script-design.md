# ECS Role OSS Upload Script Design

## Purpose

Add a standalone script that uploads local scan output files to Alibaba Cloud OSS using the RAM role assigned to the ECS instance.

## Scope

The script must be isolated from the scanner. It should not change `assess_attack_surface.py` or automatically upload after scans yet.

## Command

```bash
python3 upload_to_oss.py 20260806-140118-asm-findings.jsonl 20260806-140118-asm-findings.csv
```

The script uploads each file to:

```text
oss://$OSS_BUCKET/$OSS_PREFIX/<basename>
```

`OSS_PREFIX` defaults to `asm-findings/`.

## Configuration

Read `.env` and environment variables:

- `OSS_ENDPOINT`, required, for example `https://oss-cn-hangzhou.aliyuncs.com`
- `OSS_BUCKET`, required
- `OSS_PREFIX`, optional, defaults to `asm-findings/`
- `OSS_ROLE_NAME`, optional. If absent, discover the ECS role name from metadata.

No long-lived AccessKey should be required.

## Authentication

Use ECS metadata service:

```text
http://100.100.100.200/latest/meta-data/ram/security-credentials/
http://100.100.100.200/latest/meta-data/ram/security-credentials/{role_name}
```

The second endpoint returns temporary STS credentials:

- `AccessKeyId`
- `AccessKeySecret`
- `SecurityToken`

## Upload implementation

Use Python standard library only. Implement OSS V4 request signing for `PUT` object requests with temporary credentials and `x-oss-security-token`.

## Testing

Add unit tests for:

- `.env` loading without overriding existing environment variables.
- Role name discovery from metadata when `OSS_ROLE_NAME` is absent.
- OSS object key generation with prefix and local file basename.
- PUT request includes `x-oss-security-token` and uses the configured endpoint/bucket/object path.
