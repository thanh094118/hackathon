# TODO

- [x] Add `src/scoring/mongodb_queries.py` centralized query helper module for dashboard complex queries.
- [x] Refactor `src/dashboard/query_adapter.py` delegation to centralized MongoDB query functions.
- [x] Add delegation tests for adapter integration (`tests/test_dashboard_query_adapter.py`).
- [x] Verify dashboard import in project conda env and mock-mode adapter execution.
- [ ] Clean pre-existing out-of-scope staged/modified files in working tree before final Issue 3 review.
- [ ] Ensure `.env` is fully untracked/ignored in current workspace snapshot.

- [x] Create safety backup patches before cleanup.
- [x] Remove `.env` from Git scope and enforce ignore policy.
- [x] Sanitize `.env.example` placeholders.
- [x] Remove/revert out-of-scope files from Issue 3 diff.
- [x] Update `AGENTS.md` to current durable repository guidance.
- [x] Refresh `conversation_cache` with post-cleanup status and decisions.
- [ ] Optional final verification in target interpreter:
  - `python -m compileall src`
  - `streamlit run src/dashboard/app.py`
