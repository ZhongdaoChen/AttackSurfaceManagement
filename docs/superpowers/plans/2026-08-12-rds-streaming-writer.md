# RDS Streaming Writer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Write every scan finding to PostgreSQL RDS while JSONL and CSV are written.

**Architecture:** Add `rds_writer.py` as an isolated PostgreSQL writer module. `assess_attack_surface.py` opens the writer when RDS env vars are configured and calls it inside the existing per-finding output loop.

**Tech Stack:** Python 3 standard library plus optional runtime dependency `psycopg` on ECS, PostgreSQL RDS, JSONB.

## Global Constraints

- Local runs without RDS env vars skip DB writes.
- If RDS env vars are configured and DB insert fails, scanning fails.
- `raw JSONB` stores full finding object.
- `whitelisted BOOLEAN` is inserted for every row.
- Tests must use fake DB connections; local tests must not require RDS network access.

---

### Task 1: Create RDS writer module

**Files:** `rds_writer.py`, `test_rds_writer.py`

- [ ] Write tests for env detection, scan id generation, whitelisted calculation, and insert parameters.
- [ ] Implement `RdsFindingWriter` and helpers.
- [ ] Verify focused tests pass.

### Task 2: Integrate writer into scanner loop

**Files:** `assess_attack_surface.py`, `test_assess_attack_surface.py`

- [ ] Write test that `main()` writes JSONL/CSV and calls RDS writer once per finding.
- [ ] Open writer after output path resolution.
- [ ] Call writer in the per-finding loop after JSONL/CSV writes.
- [ ] Close writer in `finally`.
- [ ] Verify focused tests pass.

### Task 3: Docs and validation

**Files:** `README.md`

- [ ] Document RDS env vars and `psycopg[binary]` requirement.
- [ ] Run full tests.
- [ ] Commit implementation.
