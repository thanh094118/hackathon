# AGENTS.md

## Repository Status

This project is currently in **Phase 1**: a **non-ML MVP pipeline** for web access log parsing and rule-based web attack detection.

Important status:
- Phase 1 baseline is already implemented end-to-end.
- Preserve the current **package-based architecture**.
- Do **not** rebuild from scratch.
- Do **not** start Phase 2 ML unless the user explicitly requests it.

Phase 2 ML is intentionally deferred. Do not add TF-IDF, n-gram ML, embeddings, vector search, deep learning, Isolation Forest, or realtime ML inference in Phase 1 tasks.

## Entrypoints

Primary CLI:
- `python -m src.main --input <access.log> --server-type <apache|nginx|iis> --output-dir <output_dir>`

Compatibility wrapper:
- `python main.py --input <access.log> --server-type <apache|nginx|iis> --output-dir <output_dir>`

## Architecture (Preserve)

Current accepted package structure:
- `src/main.py` (pipeline orchestration CLI)
- `src/collector/`
- `src/parser/`
- `src/normalizer/`
- `src/preprocessor/`
- `src/detection/`
- `src/features/`
- `src/scoring/`
- `src/exporters/`
- `src/reporting/`

Do not revert to single-file legacy layout.
Do not recreate old modules such as:
- `src/parser.py`
- `src/scoring.py`
- `src/exporter.py`
- `src/report.py`

## Current Pipeline Outputs

Per run, the pipeline should generate:
- `raw_lines.jsonl`
- `parsed_logs.jsonl`
- `normalized_logs.jsonl`
- `normalized_logs.csv`
- `preprocessed_requests.jsonl`
- `features.csv`
- `alerts.jsonl`
- `alerts.csv`
- `report.md`
- `run_summary.json`

## Data/Schema Invariants

When modifying code, preserve these behaviors:
- Malformed log lines are preserved as records, not dropped.
- Keep `raw_log` and original URL field (`original_url` / equivalent).
- Keep `parse_status`, `parse_error`, and `error_message` where applicable.
- Keep output schemas stable across artifacts.
- Preserve `event_id` (or equivalent stable identifier) across pipeline artifacts when possible.

## Workflow Rules

Before changing code:
- Read `AGENTS.md`.
- Read relevant `conversation_cache/*` files, at minimum:
  - `conversation_cache/current_status.md`
  - `conversation_cache/known_issues.md`
  - `conversation_cache/edge_cases.md`
  - `conversation_cache/datasets.md`

After changing code:
- Update `conversation_cache/current_status.md`.
- Update relevant cache files (`decisions.md`, `todo.md`, `known_issues.md`, `edge_cases.md`, `datasets.md`) when affected.

Engineering style:
- Prefer small, focused changes.
- Add or update tests with functional changes.
- Run `pytest` after code changes.

## Commands

Environment:
- `pip install -r requirements.txt`
- `conda env create -f environment.yml`

Tests:
- `pytest -q`
- `PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider`

## Git Hygiene

Do not commit generated/local artifacts, including:
- `outputs/`
- `data/processed/`
- `__pycache__/`
- `.pytest_cache/`
- large local datasets or local-only log corpora
