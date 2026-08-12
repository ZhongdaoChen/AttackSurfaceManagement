-- PostgreSQL schema for Attack Surface Management findings.
-- Target database: AppSec_ASM

CREATE TABLE IF NOT EXISTS asm_scans (
  scan_id TEXT PRIMARY KEY,
  started_at TIMESTAMPTZ NOT NULL,
  source_file TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS asm_findings (
  id BIGSERIAL PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES asm_scans(scan_id) ON DELETE CASCADE,

  endpoint_id TEXT,
  endpoint_name TEXT,
  wiz_link TEXT,
  host TEXT,
  port INTEGER,

  cloud_platform TEXT,
  cloud_account_name TEXT,
  tag_emails TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  exposure_level TEXT,

  check_id TEXT,
  risk_level TEXT,
  whitelisted BOOLEAN NOT NULL DEFAULT FALSE,

  http_status TEXT,
  http_response TEXT,
  llm_opinion TEXT,

  evidence TEXT,
  recommendation TEXT,

  details JSONB NOT NULL DEFAULT '{}'::JSONB,
  raw JSONB NOT NULL,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_asm_findings_scan_endpoint_check
  ON asm_findings (
    scan_id,
    COALESCE(endpoint_id, ''),
    COALESCE(check_id, ''),
    COALESCE(host, ''),
    COALESCE(port, -1)
  );

CREATE INDEX IF NOT EXISTS idx_asm_findings_scan_id
  ON asm_findings(scan_id);

CREATE INDEX IF NOT EXISTS idx_asm_findings_risk_level
  ON asm_findings(risk_level);

CREATE INDEX IF NOT EXISTS idx_asm_findings_whitelisted
  ON asm_findings(whitelisted);

CREATE INDEX IF NOT EXISTS idx_asm_findings_endpoint_id
  ON asm_findings(endpoint_id);

CREATE INDEX IF NOT EXISTS idx_asm_findings_host
  ON asm_findings(host);

CREATE INDEX IF NOT EXISTS idx_asm_findings_port
  ON asm_findings(port);

CREATE INDEX IF NOT EXISTS idx_asm_findings_cloud_account_name
  ON asm_findings(cloud_account_name);

CREATE INDEX IF NOT EXISTS idx_asm_findings_tag_emails
  ON asm_findings USING GIN(tag_emails);

CREATE INDEX IF NOT EXISTS idx_asm_findings_details
  ON asm_findings USING GIN(details);

CREATE INDEX IF NOT EXISTS idx_asm_findings_raw
  ON asm_findings USING GIN(raw);
