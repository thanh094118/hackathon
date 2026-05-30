# TODO

- [x] Add standalone `src/alerts/` notification package.
- [x] Add alert event/result models, config loader, formatter, notifier implementations, and dispatcher.
- [x] Add `tests/test_alerts.py` covering flexible mapping, formatting, dispatcher behavior, dry-runs, and missing credentials.
- [x] Add placeholder-only `.env.example` alert configuration.
- [x] Add `scripts/test_alerts_manual.py` for manual alert module dry-run checks.
- [ ] Future: wire `AlertDispatcher` into the main pipeline after integration requirements are defined.

- [x] Add `src/scoring/mongodb_queries.py` centralized query helper module for dashboard complex queries.
- [x] Refactor `src/dashboard/query_adapter.py` delegation to centralized MongoDB query functions.
- [x] Add delegation tests for adapter integration (`tests/test_dashboard_query_adapter.py`).
- [x] Verify dashboard import in project conda env and mock-mode adapter execution.
- [x] Clean pre-existing out-of-scope staged/modified files in working tree before final review.
- [x] Ensure `.env` is fully untracked/ignored in current workspace snapshot.
- [x] Create safety backup patches before cleanup.
- [x] Remove `.env` from Git scope and enforce ignore policy.
- [x] Sanitize `.env.example` placeholders.
- [x] Remove/revert out-of-scope files.
- [x] Update `AGENTS.md` to current durable repository guidance.
- [x] Refresh `conversation_cache` with post-cleanup status and decisions.
- [x] Optional final verification in target interpreter:
  - [x] `python -m compileall src`
  - [x] `streamlit run src/dashboard/app.py`
- [x] Resolve "Unknown" IP display in Top Attacking IPs dashboard table by migrating aggregation pipelines to handle `source_ip` vs `ip` schema mapping.
- [x] Add dynamic dropdown filter for detection methods (All, Rules Only, ML Only, Hybrid Only) in Threat Investigator sidebar.
- [x] Map seeded attack pattern fields (category, payload_example, mitigation) to dashboard fields (attack_type, examples, remediation) to ensure Vector Search match cards resolve correctly (Type: scanner, MITRE: T1595 | T1505) instead of displaying "Unknown" or "N/A".
