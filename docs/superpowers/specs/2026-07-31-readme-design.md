# README Design

## Purpose

Add a repository `README.md` that explains how to use the Attack Surface Management scanner, how to configure Wiz and LLM credentials, and how to interpret the generated outputs.

## Audience and language

The README should be bilingual. Chinese should be the primary language for internal security and operations users. English should provide a concise mirrored summary for GitHub visitors and cross-team readers.

## Content structure

The README should include:

- Project overview.
- Feature summary.
- Repository file structure.
- Prerequisites.
- Environment variables for Wiz and optional LLM analysis.
- Common commands:
  - Export raw Wiz application endpoints.
  - Scan the first 100 endpoints.
  - Run a full scan.
  - Re-run scans from an input JSONL file.
- Output explanation:
  - JSONL findings.
  - CSV findings.
  - `Wiz链接` CSV column.
  - `risk_level` values.
- Scope clarification: the scanner currently fetches Wiz `applicationEndpoints` by project id and does not explicitly pre-filter only public/internet-facing endpoints.
- Security notes: do not commit `.env`, generated findings, caches, or credentials.
- Test command.
- Concise English section covering the same operational points.

## Constraints

- Do not include real credentials or sensitive endpoint data.
- Use commands that match the current scripts and command-line options.
- Mention that generated findings files are ignored by `.gitignore`.
- Keep the README practical and command-focused rather than architectural.

## Validation

Review `README.md` for clear commands, no placeholders, and no secrets. Run the Python unit test suite after adding the README to confirm the repository remains healthy before pushing.
