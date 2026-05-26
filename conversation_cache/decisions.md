# Decisions

## 2026-05-25 - Establish Agent Memory Files

Decision: Use `AGENTS.md` for stable long-term repository instructions and `conversation_cache/` for mutable session/project memory.

Reason: Future autonomous coding-agent sessions need a consistent startup and persistence workflow without mixing temporary session logs into stable instructions.

Tradeoffs / impact: Adds maintenance overhead, but keeps source code authoritative and gives agents a clear place to update current state.

## 2026-05-25 - Treat Pipeline Outputs As Generated Artifacts

Decision: Treat `outputs/`, `data/processed/`, caches, and model artifacts as generated/local data.

Reason: Pipeline runs overwrite generated outputs and may use local-only data.

Tradeoffs / impact: Agents must run smoke checks carefully, but this avoids accidental churn/loss of generated evidence.

## 2026-05-26 - Keep Package-Based Architecture

Decision: Keep the current package-based architecture as the accepted convention.

Reason: Phase 1 baseline is already implemented and testable in package form.

Tradeoffs / impact: Limits ad-hoc restructuring but improves maintainability and module isolation.

## 2026-05-26 - Do Not Revert To Single-File Module Layout

Decision: Do not recreate old single-file modules such as `src/parser.py`, `src/scoring.py`, `src/exporter.py`, or `src/report.py`.

Reason: Reverting would create architectural drift and duplicate logic.

Tradeoffs / impact: Requires future contributors to follow package boundaries consistently.

## 2026-05-26 - Malformed Logs Are First-Class Records

Decision: Treat malformed log lines as first-class records instead of dropping them.

Reason: Security analysis needs traceability and failure visibility.

Tradeoffs / impact: Some downstream artifacts contain parse-error rows by design.

## 2026-05-26 - Preserve Raw Log And Original URL

Decision: Preserve original request evidence fields (`raw_log`, original URL field) across stages where applicable.

Reason: Investigation and forensic workflows require original request context.

Tradeoffs / impact: Schema must explicitly carry these fields across artifacts.

## 2026-05-26 - JSONL For Intermediate Artifacts

Decision: Use JSONL for intermediate stage outputs.

Reason: JSONL keeps per-record structure and is robust for incremental processing.

Tradeoffs / impact: Less spreadsheet-friendly than CSV, but better for structured pipelines.

## 2026-05-26 - CSV For Table Exports And Future Dataset Prep

Decision: Use CSV for table-style exports (`normalized_logs.csv`, `features.csv`, `alerts.csv`) and future ML dataset preparation.

Reason: CSV is simple for analysis and tooling interoperability.

Tradeoffs / impact: Nested fields must be flattened/serialized.

## 2026-05-26 - Report Outputs For Human And Machine Summary

Decision: Keep both `report.md` (human-readable) and `run_summary.json` (machine-readable).

Reason: Security operations and automation need different summary formats.

Tradeoffs / impact: Requires summary consistency checks across both outputs.

## 2026-05-26 - Keep Phase 2 ML Separate From Phase 1 Pipeline

Decision: Defer Phase 2 ML work until explicitly requested.

Reason: Current priority is Phase 1 stability, validation, schema consistency, and rule-based baseline quality.

Tradeoffs / impact: ML capabilities are intentionally unavailable in current scope.
