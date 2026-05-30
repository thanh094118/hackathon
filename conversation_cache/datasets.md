# Datasets / Artifacts Notes

- `collector_results/*_raw_lines.jsonl` schema (current):
  - keeps: `event_id`, `line_number`, `server_type`, `raw_line`, `parse_status`
  - adds: `flags` (list), `physical_line_range` (`[start, end]`)
  - removed legacy fields: `encoding_used`, `decode_error`, `had_bom`, `was_continuation_merged`, `physical_line_start`, `physical_line_end`, raw-stage `parse_error`, raw-stage `error_message`.
- `parser_results/*_parsed_logs.jsonl` remains parser-domain schema with `parse_error`/`error_message` and parser-specific fields.
- `feature_results/*_features.csv` follows feature-only numeric schema.
- Detector artifacts:
  - `detector_results/*_alerts.jsonl|csv` store alert-only rows (`should_alert == True` records).
- Run summary artifacts:
  - `report/*_run_summary.json` includes `counts`, label distribution, top attack/rule stats, and collector counters derived from `flags`.
- ML artifacts (optional training/inference path):
  - `models/ml/binary_model.joblib`
  - `models/ml/attack_type_model.joblib`
  - `models/ml/feature_columns.json`
  - `models/ml/metadata.json`
  - `models/ml/metrics.json`
- Converter for `.txt/.log` request-block sources outputs one synthetic access-log line per request block under `data/raw/<server_type>/`.
