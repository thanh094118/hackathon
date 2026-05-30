# AGENTS.md

Operational instructions for autonomous coding agents working in this repository.

## Repository Shape

- This is a Python log-security pipeline (non-ML core) under `src/`, driven by `python -m src.main`.
- Main entrypoint is `src/main.py`:
  - always runs full flow for each input file (no stage flag).
  - supports single file or directory batch mode (`run_pipeline_batch`).
  - auto-detects server type when `--server-type` is omitted.
- Canonical flow order:
  1. collector
  2. parser
  3. normalizer
  4. preprocessor
  5. detector
  6. feature extraction
  7. risk scoring
  8. reporting/export
- Rule definitions live in `src/rules/attack_patterns.yaml`.
- Dashboard MongoDB aggregation/vector-search query library lives in `src/scoring/mongodb_queries.py`.
- Runtime artifacts are written under `outputs/` (or `--output-dir`) into module-specific folders.

## Module Responsibilities

- `src/collector/`: read input safely in binary mode, normalize line endings, merge only indented continuation lines, output logical records with metadata.
- `src/parser/`: Apache/Nginx/IIS parsers plus content-based server detection.
- `src/normalizer/`: normalize parsed fields into stable schema.
- `src/preprocessor/`: request-focused normalization/decoding for detector/features.
- `src/detection/`: YAML-driven rule engine with validation, compiled regex caching, severity/score aggregation.
- `src/features/`: handcrafted numeric feature extraction.
- `src/scoring/`: risk score/level/final labeling.
- `src/scoring/mongodb_queries.py`: centralized MongoDB query helpers for dashboard (aggregation + vector search).
- `src/reporting/`: summary and markdown report generation.
- `src/exporters/`: JSONL/CSV/Markdown writers.
- `src/converter/`: convert `.txt/.csv/.json/.jsonl` raw sources into canonical records.

## Data Contracts You Must Preserve

- Collector raw JSONL schema (current):
  - keep: `event_id`, `line_number`, `server_type`, `raw_line`, `parse_status`
  - keep/add: `flags` (list), `physical_line_range` (`[start, end]`)
  - removed legacy fields: `encoding_used`, `decode_error`, `had_bom`, `was_continuation_merged`, `physical_line_start`, `physical_line_end`
- Parser/domain records still keep `parse_error` + `error_message`.
- `feature_results/*_features.csv` is feature-only numeric model input artifact.
- Pipeline output naming convention must remain stable:
  - `collector_results/*_raw_lines.jsonl`
  - `parser_results/*_parsed_logs.jsonl`
  - `normalizer_results/*_normalized_logs.jsonl|csv`
  - `preprocessor_results/*_preprocessed_requests.jsonl`
  - `detector_results/*_alerts.jsonl|csv`
  - `feature_results/*_features.csv`
  - `report/*_report.md`
  - `report/*_run_summary.json`

## Coding Conventions

- Follow existing module boundaries; avoid cross-module coupling for quick fixes.
- Keep parser API streaming (`parse_lines` iterator semantics) and compatible with current tests.
- Keep server detection behavior stable unless task explicitly asks to change it:
  - IIS header check first (`#Fields` / `#Software`)
  - Apache vs Nginx by parser success counts
  - Apache default when uncertain/empty
- Keep collector `read_lines()` and `read_records()` behavior aligned through shared internal logic.
- When changing output schema, audit downstream consumers in normalizer/preprocessor/detection/scoring/reporting/tests.
- Prefer explicit, backward-compatible field additions over field renames/removals.
- Keep MongoDB aggregation/vector-search logic centralized in `src/scoring/mongodb_queries.py`; `src/dashboard/query_adapter.py` should mainly normalize/fallback for UI compatibility.

## Workflow Rules

- At task start, read this `AGENTS.md` and `conversation_cache/current_status.md`, `conversation_cache/decisions.md`, `conversation_cache/todo.md`.
- Check `conversation_cache/known_issues.md`, `edge_cases.md`, `datasets.md` when task touches parser/collector/schema/data assumptions.
- Use source code/tests as authority if cache notes are stale; then update cache to match reality.
- Keep durable process/architecture guidance in `AGENTS.md`.
- Keep transient state, progress, blockers, and next steps in `conversation_cache/*`.

## Persistence Workflow

- Before coding:
  - reread `AGENTS.md`
  - reread relevant `conversation_cache/*`
- After substantial coding sessions:
  - update `conversation_cache/current_status.md` with current results and verification state
  - append durable decisions to `conversation_cache/decisions.md`
  - refresh checklist in `conversation_cache/todo.md`

## Testing And Checks

- Primary test command:
  ```bash
  pytest -q tests
  ```
- Parser-focused regression:
  ```bash
  pytest -q tests/test_parser.py
  ```
- Collector-focused regression:
  ```bash
  pytest -q tests/test_collector.py
  ```
- Full repository `pytest -q` may include optional test areas outside `tests/` and fail if optional deps are missing.

## Known Risks / Fragile Areas

- `detect_server_type(...)` defaults to Apache for uncertain or empty samples.
- Pipeline currently materializes full lists in memory (not fully streaming end-to-end).
- Apache and Nginx parser implementations are intentionally separate but similar; edits can drift if not mirrored carefully.
- Any external consumer of old collector raw fields must migrate to `flags` + `physical_line_range`.
- Large or mixed-format inputs can produce parser ambiguity; preserve current error-tolerant behavior unless explicitly changing it.

## Dangerous Areas

- `outputs/` contains generated artifacts and can be overwritten across runs.
- `data/` may contain large input fixtures; avoid destructive edits unless explicitly requested.
- `src/rules/attack_patterns.yaml` directly changes detection behavior; validate with tests after editing.
- `tests/test_pipeline.py` and end-to-end tests can touch many modules at once; run focused tests first for local changes.

## Memory File Update Format

- `conversation_cache/current_status.md`: latest session state, blockers, verification outcomes.
- `conversation_cache/decisions.md`: durable architecture/behavior decisions and rationale.
- `conversation_cache/todo.md`: active/deferred/completed work items.
- `conversation_cache/known_issues.md`: recurring bugs and limitations.
- `conversation_cache/edge_cases.md`: parsing/schema edge cases that must be preserved.
- `conversation_cache/datasets.md`: dataset and artifact contract notes.
