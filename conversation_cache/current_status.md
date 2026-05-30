# Current Status

## Current Objective

Maintain and harden the already-implemented Phase 1 non-ML pipeline; do not rebuild architecture or start ML.

## Completed Work

- Phase 1 non-ML pipeline is implemented end-to-end.
- Primary CLI entrypoint exists at `src/main.py`.
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
- Parser hardening update completed:
  - Apache parser now requires full-line match (rejects trailing unexpected fields).
  - Nginx parser now supports two profiles:
    - combined
    - combined + trailing custom fields
  - Added parser tests for trailing-field rejection, custom-tail acceptance, missing field failure, and field-order mismatch failure.
- Latest test status:
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
- ML implementation remains deferred to Phase 2 unless explicitly requested.
