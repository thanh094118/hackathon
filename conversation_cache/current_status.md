# Current Status

## Current Objective

Maintain and harden the already-implemented Phase 1 pipeline while keeping the new ML training/inference path available and validated.

## Completed Work

- Phase 1 non-ML pipeline is implemented end-to-end.
- Primary CLI orchestration now exists at `src/main.py` and wires collector, parser, normalizer, preprocessor, feature extraction, rule detection, risk scoring, export, and reporting.
- ML training/inference package is now started at `src/ml/` with a runnable CAPEC training entrypoint and pipeline-side ML prediction hook.
- Artifact folder `models/ml/` now contains trained CAPEC artifacts:
  - `binary_model.joblib`
  - `attack_type_model.joblib`
  - `feature_columns.json`
  - `metrics.json`
  - `metadata.json`
- Training code now computes hold-out evaluation metrics for binary attack detection and attack-type classification and persists them into `metadata.json` on retrain.
- `main.py` is the compatibility wrapper for `python main.py ...` execution.
- Pipeline generates all required artifacts:
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
- CSV input routing update completed:
  - CAPEC-style `.csv` inputs are converted through the existing converter first, then processed by the same parser/normalizer/detector/export pipeline.
  - Output schema remains unchanged and still uses the existing server-type prefixing convention.
- Pipeline smoke tests now pass for file input, folder input, and CAPEC CSV input.
- Parser hardening update completed:
  - Apache parser now requires full-line match (rejects trailing unexpected fields).
  - Nginx parser now supports two profiles:
    - combined
    - combined + trailing custom fields
  - Added parser tests for trailing-field rejection, custom-tail acceptance, missing field failure, and field-order mismatch failure.
- Latest test status:
- `python -m src.main --input <sample.log> --output-dir <tmp> --rules src/rules/attack_patterns.yaml --ml-enable --ml-model-dir models/ml` -> passed smoke test and produced `ml_results/`
- `pytest -q tests/test_ml_training.py tests/test_pipeline.py tests/test_exporters_reporting.py` -> 7 passed
- `pytest -q tests/test_pipeline.py` -> 3 passed
- `pytest -q tests/test_exporters_reporting.py` -> 3 passed
- `pytest --ignore=tests/test_ai_inference_pipeline.py -q` -> 216 passed
  - `tests/test_ai_inference_pipeline.py` fails to collect due to missing `test_pipeline` module in remote main.

## Blockers

- No critical blockers confirmed.
- IIS sample format coverage still needs validation against real W3C IIS logs.
- `tests/test_ai_inference_pipeline.py` is broken upstream due to a missing package (`test_pipeline`).

## Next Recommended Step

Focus on validation, hardening, real-log testing, schema stability, rule expansion, and documentation improvements.

## Files Modified

- `src/main.py`
- `src/converter/convert_flow.py`
- `conversation_cache/current_status.md`
- `conversation_cache/known_issues.md`

## Checks Run / Skipped

- Ran: `pytest --ignore=tests/test_ai_inference_pipeline.py -q` (passed: 216 tests)
- Ran: `pytest -q tests/test_pipeline.py` (passed: 3 tests)
- Ran: `pytest -q` (blocked by pre-existing `tests/test_ai_inference_pipeline.py` collection error)
- ML implementation is now active and trainable from the CAPEC run artifacts.
