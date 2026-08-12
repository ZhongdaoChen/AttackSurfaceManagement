# Attack Surface Management Scanner

用于从 Wiz 拉取 Application Endpoints，并对暴露的 HTTP/HTTPS 服务做基础攻击面检查、重定向跟随分析、敏感内容启发式检测，以及可选的 LLM 辅助判断。

This repository contains a Python-based scanner that exports Wiz Application Endpoints, checks reachable HTTP/HTTPS services, follows redirects, detects potentially sensitive exposure, and optionally uses an OpenAI-compatible LLM for content review.

## 功能概览

- 从 Wiz GraphQL API 拉取 `applicationEndpoints`。
- 支持把 Wiz 原始 endpoint 导出为 JSONL。
- 对端口 80、443 和非标准开放端口生成 findings；非标准开放端口会先尝试 HTTPS/HTTP 内容探测，再按内容或 LLM 结果判断风险。
- 对 301、302、303、307、308 重定向继续 follow，并分析最终目标。
- 对 HTTPS 内容做登录页、404、目录列表、疑似 secret、错误栈等判断。
- 可选启用 LLM 对 200 响应进行敏感数据暴露判断。
- 输出 JSONL findings 和 CSV findings。
- CSV 中包含 `Wiz链接`，可点击跳转到对应 Wiz endpoint 页面。

## 文件结构

| 文件 | 说明 |
| --- | --- |
| `wiz_auth_poc.py` | Wiz OAuth、GraphQL 连通性检查、Application Endpoints 导出 |
| `assess_attack_surface.py` | 主扫描器：读取/拉取 endpoints，执行检查，输出 JSONL/CSV |
| `test_wiz_auth_poc.py` | Wiz API 相关单元测试 |
| `test_assess_attack_surface.py` | 扫描器单元测试 |
| `command.txt` | 常用全量扫描命令示例 |
| `docs/superpowers/` | 设计和实现计划文档 |

## 前置条件

- Python 3.11+。
- 可访问 Wiz API。
- 如需 LLM 判断，需要 OpenAI-compatible API key，例如 DashScope/Qwen。

本项目只使用 Python 标准库；如果系统 CA 证书不可用，代码会尝试使用 `certifi`。

## 环境变量

### Wiz

| 变量 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `WIZ_CLIENT_ID` | 是 | 无 | Wiz OAuth client id |
| `WIZ_CLIENT_SECRET` | 是 | 无 | Wiz OAuth client secret |
| `WIZ_API_URL` | 否 | `https://api.eu7.app.wiz.io/graphql` | Wiz GraphQL API |
| `WIZ_AUTH_URL` | 否 | `https://auth.app.wiz.io/oauth/token` | Wiz OAuth token endpoint |
| `WIZ_API_AUDIENCE` | 否 | `wiz-api` | OAuth audience |
| `WIZ_PROJECT_ID` | 否 | `242f91dd-f1c6-573f-b8b4-678df5581477` | 查询的 Wiz project id |
| `WIZ_TIMEOUT_SECONDS` | 否 | `30` | Wiz API 请求超时 |
| `WIZ_CA_BUNDLE` | 否 | 自动检测 | 自定义 CA bundle |

可以把这些变量放在本地 `.env` 文件中。不要提交 `.env`。

### LLM（可选）

| 变量 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `LLM_API_KEY` / `DASHSCOPE_API_KEY` / `QWEN_API_KEY` | 默认必填；使用 `--disable-llm` 时不需要 | 无 | OpenAI-compatible API key |
| `LLM_BASE_URL` | 否 | `https://dashscope.aliyuncs.com/compatible-mode/v1` | OpenAI-compatible base URL |
| `LLM_MODEL` | 否 | `qwen-plus` | 模型名称 |

`--timeout` 默认是 `30`，`--insecure-tls` 和 `--enable-llm` 默认开启。需要关闭时可使用 `--secure-tls` 或 `--disable-llm`。

### OSS 上传（可选）

如果 ECS 已绑定可写 OSS 的 RAM Role，可以用独立脚本上传生成的 findings 文件。`.env` 中配置：

| 变量 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `OSS_ENDPOINT` | 是 | 无 | OSS endpoint，例如 `https://oss-cn-hangzhou.aliyuncs.com` |
| `OSS_BUCKET` | 是 | 无 | OSS bucket 名称 |
| `OSS_PREFIX` | 否 | `asm-findings/` | 上传到 bucket 内的路径前缀 |
| `OSS_ROLE_NAME` | 否 | 自动从 ECS metadata 发现 | ECS 绑定的 RAM Role 名称 |

### RDS PostgreSQL 写入（可选）

如果配置了 RDS 变量，扫描器会在写 JSONL/CSV 的同时，把每条 finding 写入 PostgreSQL：

| 变量 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `RDS_HOST` | 是 | 无 | RDS PostgreSQL 地址 |
| `RDS_PORT` | 否 | `5432` | RDS PostgreSQL 端口 |
| `RDS_DB` | 是 | 无 | 数据库名，例如 `AppSec_ASM` |
| `RDS_USER` | 是 | 无 | 数据库用户名 |
| `RDS_PASSWORD` | 是 | 无 | 数据库密码 |
| `RDS_SSLMODE` | 否 | `prefer` | PostgreSQL SSL mode |

ECS 上需要安装 Python PostgreSQL 驱动：

```bash
pip3 install "psycopg[binary]"
```

## 常用命令

### 1. 检查 Wiz 认证和 GraphQL 连通性

```bash
python3 wiz_auth_poc.py
```

### 2. 导出 Wiz 原始 Application Endpoints

```bash
python3 wiz_auth_poc.py list-application-endpoints > wiz-application-endpoints.jsonl
```

### 3. 扫描前 100 个 endpoint

```bash
python3 assess_attack_surface.py \
  --output asm-findings-limit100.jsonl \
  --csv-output asm-findings-limit100.csv \
  --limit 100
```

### 4. 全量扫描

```bash
python3 assess_attack_surface.py
```

未指定 `--output` 时，会自动生成 `YYYYMMDD-HHMMSS-asm-findings.jsonl` 和 `YYYYMMDD-HHMMSS-asm-findings.csv`。

如果 ECS 已配置 OSS 变量和 RAM Role，扫描结束后会自动上传本次生成的 JSONL/CSV：

```bash
python3 assess_attack_surface.py
```

如需临时禁止上传，可加 `--no-upload-oss`。也可以显式加 `--upload-oss` 强制要求上传。

### 5. 使用已导出的 input 重新扫描

```bash
python3 assess_attack_surface.py \
  --input wiz-application-endpoints.jsonl \
  --output asm-findings-full-latest.jsonl \
  --csv-output asm-findings-full-latest.csv
```

### 6. 上传 findings 到 OSS

```bash
python3 upload_to_oss.py \
  20260806-140118-asm-findings.jsonl \
  20260806-140118-asm-findings.csv
```

## 输出说明

### JSONL

`--output` 生成 JSON Lines，每行一个 finding。未指定 `--output` 时会自动生成时间戳文件名。常见字段包括：

- `endpoint_id`
- `endpoint_name`
- `host`
- `port`
- `cloudPlatform`
- `cloudAccountName`
- `tagEmails`
- `exposureLevel`
- `check_id`
- `risk_level`
- `evidence`
- `recommendation`
- `details`

### CSV

`--csv-output` 生成适合人工 review 的 CSV。未指定 `--output` 时会自动生成同前缀 CSV；显式指定 `--output` 时，只有同时传 `--csv-output` 才生成 CSV。当前列包括：

- `endpoint_name`
- `Wiz链接`
- `端口号`
- `cloudPlatform`
- `CloudAccount`
- `TagEmails`
- `http状态码`
- `http response`
- `LLM意见`
- `risk_level`

`Wiz链接` 会根据 `endpoint_id` 生成 Wiz 控制台链接，点击后可打开对应 application endpoint 页面。

非标准端口的 `http response` 会优先显示 HTTPS/HTTP 探测结果，例如 `https failed: timed out; http returned HTTP 200`。

### risk_level

- `high`：发现疑似敏感内容暴露，例如目录列表、secret-like value、错误栈、备份文件线索；或敏感非标准端口内容不可判定且无低优先级订阅例外。
- `medium`：需要人工 review，例如非登录页且无明确敏感信号的 HTTPS 页面、带信息泄露线索的 404。
- `low`：当前根路径未观察到直接敏感暴露，或属于低优先级网络/配置问题，例如登录页、干净 404、connection reset、HTTPS 证书校验失败、HTTP 80 未强制跳转 HTTPS、非敏感非标准端口内容不可判定。
- `unknown`：检查器或网络异常导致无法判断。

## 当前检查范围说明

脚本默认从 Wiz 拉取指定 project 下的 `applicationEndpoints`：

```python
filterBy: {"project": [WIZ_PROJECT_ID]}
```

拉取后，代码会在本地只保留 `exposureLevel=HIGH` 或 `exposureLevel=MEDIUM` 的 endpoint 进入扫描。

如果使用 `--input` 扫描已导出的 JSONL，则会扫描输入文件中的所有 endpoint，不再额外按 `exposureLevel` 过滤。

## 安全注意事项

- 不要提交 `.env`、API key、client secret 或 access token。
- 不要提交生成的 findings 文件；`asm-findings-*.jsonl` 和 `asm-findings-*.csv` 已在 `.gitignore` 中忽略。
- Findings 可能包含 endpoint、响应摘要、LLM 判断和敏感片段，分享前需要脱敏。
- `--insecure-tls` 仅用于内容 triage，不代表生产环境可以忽略证书问题。
- `--timeout` 默认是 `30`，`--insecure-tls` 和 `--enable-llm` 默认开启。需要关闭时可使用 `--secure-tls` 或 `--disable-llm`。

## 测试

```bash
python3 -m unittest test_assess_attack_surface.py
python3 -m unittest test_wiz_auth_poc.py
```

## English summary

This project scans Wiz Application Endpoints for attack-surface review. It can fetch endpoints from Wiz, export raw endpoint JSONL, assess reachable HTTP/HTTPS services, follow redirects, detect sensitive exposure signals, and optionally ask an OpenAI-compatible LLM to review HTTP response content.

Common commands:

```bash
# Export raw Wiz endpoints
python3 wiz_auth_poc.py list-application-endpoints > wiz-application-endpoints.jsonl

# Scan the first 100 endpoints
python3 assess_attack_surface.py \
  --output asm-findings-limit100.jsonl \
  --csv-output asm-findings-limit100.csv \
  --limit 100

# Full scan
python3 assess_attack_surface.py
```

Required Wiz environment variables are `WIZ_CLIENT_ID` and `WIZ_CLIENT_SECRET`. LLM review is enabled by default and requires one of `LLM_API_KEY`, `DASHSCOPE_API_KEY`, or `QWEN_API_KEY`; use `--disable-llm` to turn it off.

Generated findings are ignored by git because they may contain endpoint or exposure data. Do not commit `.env`, credentials, raw scan outputs, or sensitive response snippets.
