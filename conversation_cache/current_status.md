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
- Parser hardening update completed:
  - Apache parser now requires full-line match (rejects trailing unexpected fields).
  - Nginx parser now supports two profiles:
    - combined
    - combined + trailing custom fields
  - Added parser tests for trailing-field rejection, custom-tail acceptance, missing field failure, and field-order mismatch failure.
- Latest test status:
  - `pytest -q` -> 25 passed
  - `PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider` -> 25 passed

## Blockers

- No critical blockers confirmed.
- IIS sample format coverage still needs validation against real W3C IIS logs.

## Next Recommended Step

Focus on validation, hardening, real-log testing, schema stability, rule expansion, and documentation improvements.

## Files Modified

- `src/parser/apache_parser.py`
- `src/parser/nginx_parser.py`
- `tests/test_parser.py`
- `conversation_cache/current_status.md`
- `conversation_cache/edge_cases.md`
- `conversation_cache/known_issues.md`

## Checks Run / Skipped

- Ran: `pytest -q tests/test_parser.py` (passed: 9 tests)
- Ran: `PYTHONDONTWRITEBYTECODE=1 pytest -q tests/test_pipeline.py` (passed: 1 test)
- Ran: `pytest -q` (passed: 25 tests)
- Ran: `PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider` (passed: 25 tests)
- ML implementation remains deferred to Phase 2 unless explicitly requested.
