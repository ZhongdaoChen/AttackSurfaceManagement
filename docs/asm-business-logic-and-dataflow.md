# ASM 攻击面管理 — 业务逻辑与数据流总结

> 本文总结 Attack Surface Management（ASM）系统的完整业务逻辑与数据流。
> 代码基线：git HEAD（`e26f98d`）。

## 1. 系统定位

从 Wiz 拉取对外暴露的 Application Endpoints，对可达的 HTTP/HTTPS 服务做基础攻击面检查
（重定向跟随、敏感内容启发式、非标准端口探测），可选用 OpenAI 兼容 LLM（DashScope/Qwen）
做内容级判断；结果多路扇出到 JSONL/CSV 文件、阿里云 OSS、RDS PostgreSQL；
Streamlit Dashboard 以 RDS 为单一事实源，向 AppSec 团队展示当前攻击面、历史趋势和白名单治理。

## 2. 组件清单

| 组件 | 职责 |
| --- | --- |
| `wiz_auth_poc.py` | Wiz OAuth（client_credentials）换 token；GraphQL 连通性检查；分页导出 `applicationEndpoints`；按 cloud account 查询 tag emails 做 endpoint 富化 |
| `assess_attack_surface.py` | 主扫描编排器：输入（Wiz 实时拉取或 `--input` JSONL）→ 4 个 checker 检查 → 多路输出（JSONL/CSV/RDS/OSS） |
| `rds_writer.py` | RDS 写入：`asm_scans` / `asm_findings` / `asm_current_findings` 生命周期维护、whitelist 标记、finalize 标记 resolved、Teams 高风险通知 |
| `upload_to_oss.py` | ECS RAM Role 凭证发现 + OSS V4 签名上传 findings 文件 |
| `asm_dashboard/` | Streamlit Dashboard：密码门禁 + 三个页面（Current Status / Historical Results / Whitelist Rules） |
| `schema.sql` | PostgreSQL 表结构（`AppSec_ASM` 库，4 张表） |

扫描核心只依赖 Python 标准库；RDS 写入需要 `psycopg`；Dashboard 需要 `streamlit/pandas/plotly`。

## 3. 端到端数据流

```
                          [.env / 环境变量]
                Wiz 凭据 · LLM key · OSS · RDS · DASHBOARD_PASSWORD · TEAMS_WEBHOOK_URL
                                    │
                                    ▼
 ┌──────────────────────── Wiz 数据源 ────────────────────────┐
 │ wiz_auth_poc.fetch_access_token   OAuth client_credentials │
 │ iter_application_endpoints        GraphQL 分页 (project 过滤)│
 │   └─ 客户端过滤 exposureLevel ∈ {HIGH, MEDIUM}              │
 │ enrich_endpoint_with_tag_emails   cloud account tag 邮箱(带缓存)│
 └────────────────────────────┬───────────────────────────────┘
                              │ endpoints（--input 时读 JSONL，不再过滤）
                              ▼
 ┌────────────────── assess_attack_surface 扫描核心 ──────────────────┐
 │ 对每个 endpoint 依次跑 checkers（异常不中断，记 <check_id>_error=unknown）│
 │  ① NonStandardPortChecker   portStatus=OPEN 且 port ∉ {80,443}      │
 │  ② HttpRedirectChecker      port=80                                 │
 │  ③ HttpsContentChecker      port=443                                │
 │  ④ LlmSensitiveContentChecker  仅 LLM 启用且复用到的 HTTP 200 摘要    │
 │ 探测直连目标服务；重定向 301/302/303/307/308 最多跟随 5 跳并分析最终目标 │
 └──────────────┬─────────────────────────────────────────────────────┘
                │ findings（每条：endpoint 信息 + check_id + risk_level + evidence + details）
                ├──────────────▶ JSONL 文件（默认时间戳文件名 YYYYMMDD-HHMMSS-asm-findings.jsonl）
                ├──────────────▶ CSV 文件（人工 review 列，含可点击「Wiz链接」）
                │                     │
                │                     ▼  扫描结束后（env 配置即默认开启，可 --no-upload-oss）
                │               upload_to_oss：ECS metadata 发现 RAM Role → STS 凭证 → OSS V4 签名 PUT
                │
                └──────────────▶ rds_writer（RDS env 配齐即开启）
                                  ├─ INSERT asm_scans（scan_id = 输出文件名前缀）
                                  ├─ 每条 finding：whitelisted 判定 → INSERT asm_findings（唯一索引去重）
                                  ├─ 历史插入成功 → UPSERT asm_current_findings（finding_key=sha256）
                                  ├─ finalize()：本轮未再现的 active 行 → resolved_at/resolved_scan_id
                                  └─ notify_new_high_risks()：本轮新增 high → Teams Adaptive Card
                                                              （webhook 失败只告警不阻断扫描）
                                                    │
                                                    ▼
                                    RDS PostgreSQL（单一事实源）
                                                    │
                                                    ▼
                              Streamlit Dashboard（DASHBOARD_PASSWORD 门禁）
                                ├─ Current Status    当前 active 且非 whitelisted
                                ├─ Historical Results 按扫描日期回看（含 whitelisted）
                                └─ Whitelist Rules   endpoint_name + port 规则创建/停用
```

## 4. 检查逻辑矩阵

### 4.1 非标准开放端口 — `non_standard_open_port`

触发条件：`portStatus == OPEN` 且端口不是 80/443。

1. 先 HTTPS 后 HTTP 探测（各 5s 超时），任一成功即进入「内容判定」（见 4.4），
   `http_probe_result` 记录如 `https failed: timed out; http returned HTTP 200`。
2. 两种协议都探测失败 → 兜底 finding：
   - 订阅/账号在 `LOW_RISK_SUBSCRIPTIONS` 例外集 → `low`（记录并持续监控）；
   - 否则 → `high`（要求关端口或 allowlist/VPN/WAF 收敛）。

### 4.2 HTTP 80 — `http_redirect`

- 返回重定向状态（301/302/303/307/308）→ 跟随重定向链，对**最终目标**做内容判定（4.4）；
  跟随失败 → `http_redirect_follow_error`（medium）。
- 未强制跳转 HTTPS → `http_without_https_redirect`（low）。

### 4.3 HTTPS 443 — `https_content`

- TLS 证书校验失败 → `https_tls_certificate_error`（low）。
- 连接被 reset → `https_connection_reset`（low）。
- 重定向 → 同 4.2 跟随并分析最终目标。
- 其他状态 → 内容判定（4.4）。

### 4.4 内容判定 `content_findings_for_response`

对最终响应做本地启发式；**LLM 启用且状态 200 时跳过本地启发式**，交由 LLM checker 出唯一 finding。

| 观察 | check_id | risk |
| --- | --- | --- |
| 404 且无泄露线索 | `https_not_found` | low |
| 404 但 exposureLevel=HIGH / Server、X-Powered-By 带版本 / body 含框架版本或 internal、stack trace、debug、bucket 等关键词 | `https_not_found_review` | medium |
| body 命中敏感信号：`index of /`（目录列表）、secret/api_key/token/private_key 赋值模式、Python/通用错误栈、backup.(zip\|tar\|tgz\|gz\|sql) | `https_sensitive_content_heuristic` | high |
| 登录页（password 输入框或 login/sign in 文案） | `https_login_page` | low |
| 其余可达 200 | `https_review_required` | medium |

### 4.5 LLM 判定 — `llm_sensitive_content`

- 复用 checker 阶段缓存的响应摘要（`context.response_summaries`，body 截断到上限）。
- OpenAI 兼容客户端（默认 DashScope `qwen-plus`，`temperature=0`），system prompt 固定为
  「评估敏感数据泄露，只返回 JSON」；返回 `risk_level(low|medium|high|unknown)/reason/evidence/recommendation`。
- evidence 要求：无敏感内容时给简短中文结论；有敏感内容时只摘敏感片段，不贴全量响应。

### 4.6 risk_level 语义

- `high`：疑似敏感内容暴露；或敏感非标准端口内容不可判定且无订阅例外。
- `medium`：需人工 review（非登录页的可达页面、带泄露线索的 404、重定向跟随失败）。
- `low`：根路径无直接敏感暴露（登录页、干净 404、connection reset、证书错误、80 未跳 HTTPS、低优先级订阅例外）。
- `unknown`：checker/网络异常。

## 5. 存储模型与 finding 生命周期

### 5.1 表结构（schema.sql）

| 表 | 语义 |
| --- | --- |
| `asm_scans` | 一次扫描一条（scan_id、started_at、source_file） |
| `asm_findings` | **历史全量**：每扫描每 finding 一行；唯一索引 `(scan_id, endpoint_id, check_id, host, port)` 去重 |
| `asm_current_findings` | **当前状态视图态**：主键 `finding_key = sha256(endpoint_id, check_id, host, port)`；带 first_seen / last_seen / seen_count / resolved_at |
| `asm_whitelist_rules` | Dashboard 创建的白名单（endpoint_name + port 可空、reason、operator、active、停用审计字段） |

### 5.2 单条 finding 的状态机

```
              本轮扫描命中                      本轮未再现
 (不存在) ───────────────▶ active ─────────────────────────▶ resolved（mitigated）
    ▲                        │  ▲                                  │
    │                        │  └── 再现：seen_count+1、刷新 last_seen、
    │                        │       resolved_at 重新置 NULL（复活）
    │                        ▼
    └───── whitelisted=true（写入时标记；dashboard 只展示 active 且非 whitelisted）
```

- **写入时**：`is_whitelisted_finding`（details.subscription ∈ `LOW_RISK_SUBSCRIPTIONS`）
  或 `dashboard_whitelisted`（存在 active 的 endpoint_name+port 规则）→ `whitelisted=true`。
- **UPSERT current**：新 key → 插入并置 first/last seen；已存在 → 全量刷新内容字段、
  `seen_count+1`、`resolved_at=NULL`（resolved 后复活）。
- **finalize**：`last_seen_scan_id <> 本次 AND resolved_at IS NULL` 的行置 `resolved_at`，
  即「本轮没扫到 = 已缓解」，构成 cumulative mitigated 指标。

### 5.3 Teams 高风险通知

finalize 后查询 `first_seen_scan_id = 本次 AND risk_level='high' AND resolved_at IS NULL`，
有则组装 Adaptive Card（最多展示前 N 条，含 host/port/account/evidence/recommendation 与首个 Wiz 链接 action）
POST 到 `TEAMS_WEBHOOK_URL`。**失败只打印异常类型，绝不阻断扫描**（避免泄露 webhook 信息）。

## 6. Dashboard 语义

- 门禁：`DASHBOARD_PASSWORD`；未配置直接报错页；session_state 记录 authenticated。
- **Current Status**：数据源 `asm_current_findings WHERE resolved_at IS NULL AND whitelisted = FALSE`。
  - KPI：Active Attack Surface / Active High / Newly Identified This Month /
    Cumulative Mitigated / Sensitive Exposure 80/443（`llm_sensitive_content` 且端口 80/443 的 high）/
    Current Non-standard Ports。
  - Exposure Trend：每个扫描点两条线 —— active high 数；cumulative mitigated 数
    （resolved_at ≤ 扫描时刻，或 whitelist 生效时刻 ≤ 扫描时刻）。
    趋势 SQL 把两个聚合**分开算再 join**，避免双扇出 join 打爆 `temp_file_limit`（历史教训）。
  - findings 表：行内展开 JSON 详情；可对行创建白名单（写 `asm_whitelist_rules` 并即时作用于展示）。
- **Historical Results**：按扫描日期查 `asm_findings`，含 whitelisted 记录，筛选 + 分页（page_size 上限 200）。
- **Whitelist Rules**：展示规则、支持停用（记录停用人/原因/时间）。
  **停用只影响未来扫描的标记，不回滚已经写成 whitelisted 的历史 findings。**

## 7. 输出格式

- **JSONL**：一行一个 finding，字段含 endpoint_id/name、host、port、cloudPlatform、
  cloudAccountName、tagEmails、exposureLevel、check_id、risk_level、evidence、recommendation、details。
- **CSV**：面向人工 review —— endpoint_name、Wiz链接（按 endpoint_id 拼控制台 URL）、端口号、
  cloudPlatform、CloudAccount、TagEmails、http状态码、http response（非标准端口优先显示探测结果摘要）、
  LLM意见、risk_level。
- **OSS**：`{prefix}{basename}`，STS 临时凭证 + SigV4 风格签名；可 `--no-upload-oss` / `--upload-oss` 覆盖自动判断。

## 8. 关键环境变量

| 域 | 变量 |
| --- | --- |
| Wiz | `WIZ_CLIENT_ID`、`WIZ_CLIENT_SECRET`（必填）；`WIZ_API_URL`、`WIZ_AUTH_URL`、`WIZ_API_AUDIENCE`、`WIZ_PROJECT_ID`、`WIZ_TIMEOUT_SECONDS`、`WIZ_CA_BUNDLE` |
| LLM | `LLM_API_KEY` / `DASHSCOPE_API_KEY` / `QWEN_API_KEY`；`LLM_BASE_URL`（默认 DashScope）、`LLM_MODEL`（默认 qwen-plus） |
| OSS | `OSS_ENDPOINT`、`OSS_BUCKET`（配齐即自动上传）；`OSS_PREFIX`、`OSS_ROLE_NAME` |
| RDS | `RDS_HOST`、`RDS_DB`、`RDS_USER`、`RDS_PASSWORD`（配齐即写库）；`RDS_PORT`、`RDS_SSLMODE` |
| Dashboard | 同 RDS + `DASHBOARD_PASSWORD` |
| 通知 | `TEAMS_WEBHOOK_URL`（配置即启用新增 high 通知） |

默认开关：`--timeout 30`、`--insecure-tls` 与 `--enable-llm` 默认开启（可用 `--secure-tls` / `--disable-llm` 关闭）。

## 9. 安全与容错设计要点

- `.env`、凭据、findings 文件一律不入库（.gitignore）；findings 含敏感片段，分享前需脱敏。
- `--insecure-tls` 仅用于内容 triage，不作为生产控制；证书问题单独出 low finding 提示修复。
- 每个 checker 独立 try/except：单 endpoint 异常只产生 `unknown` finding，不中断整轮扫描。
- RDS 写入对 `\x00` 做剥离（PostgreSQL 不接受 NUL）；连接串按 libpq 规则转义密码。
- OSS/RDS/Teams 均为「env 配置即启用、CLI 可显式覆盖」的可选扇出，缺一项不影响其他输出。
- 历史扫描用 `--input` 重放时不再做 exposureLevel 过滤（输入即全量）。
