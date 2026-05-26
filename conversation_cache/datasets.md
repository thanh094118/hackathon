# Datasets

## Phase 1 Requirements

Current Phase 1 validation requires raw `access.log` samples from:
- Apache
- Nginx
- IIS

Labeled ML datasets are **not required** for Phase 1.

## Phase 1 Dataset Purpose

In Phase 1, datasets are used to validate:
- collector behavior
- parser robustness
- normalizer output
- preprocessor transformations
- rule-based detection behavior
- export artifacts (JSONL/CSV)
- reporting outputs (`report.md`, `run_summary.json`)

## Rules Dataset

- Current rule path: `configs/rules.yaml`
- Alternate/legacy-compatible rule path used by existing code may still include `data/labels/attack_patterns.yaml`

## Output Validation Targets

Expected per-run artifacts:
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

## Phase 2 Outlook

Phase 2 may later use labeled benign/anomaly datasets for ML training and evaluation, but this is intentionally deferred.
