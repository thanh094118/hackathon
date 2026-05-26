# Todo

## High Priority

- Verify actual CLI behavior against `README.md`.
- Run `pytest`.
- Test with small Apache, Nginx, and IIS sample logs.
- Verify malformed lines are preserved.
- Verify parser failure does not crash the pipeline.
- Verify output files are generated with stable schema.
- Verify `configs/rules.yaml` is loaded and used.
- Verify `event_id` (or stable identifiers) connect records across artifacts.
- Verify `report.md` and `run_summary.json` summarize counts correctly.

## Medium Priority

- Add more edge cases for URL encoding, double encoding, empty query, suspicious user-agent, long URL, missing fields, invalid status code.
- Add sample logs under `data/sample/` if not already present.
- Improve README usage examples.
- Expand rule-based detection patterns carefully.
- Add schema documentation for output artifacts.

## Deferred

- TF-IDF
- n-gram
- Logistic Regression
- SVM
- Naive Bayes
- Isolation Forest
- embeddings
- vector search
- deep learning
- realtime ML inference
