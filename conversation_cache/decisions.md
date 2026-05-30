# Decisions (2026-05-30)

- Centralize dashboard complex MongoDB logic in `src/scoring/mongodb_queries.py` and keep `src/dashboard/query_adapter.py` focused on:
  - env/mode handling
  - connection/fallback behavior
  - response normalization for Streamlit UI.
- Delegate these adapter methods to Issue 2.3 query library when available:
  - `find_similar_attack_patterns`
  - `get_active_campaigns`
  - `get_attack_timeline`
  - `get_attack_type_distribution`
  - `get_top_attacking_ips`
- Keep graceful degradation:
  - mock mode remains first-class (`DASHBOARD_USE_MOCK=1`)
  - missing MongoDB / missing vector index / helper failures must return safe empty-or-fallback data instead of crashing UI.

- Keep this branch as Issue 3 frontend/dashboard-only; exclude backend, ML, data, infra, and unrelated test changes.
- Never track local `.env` in Git; enforce ignore rules with:
  - `.env`
  - `.env.*`
  - `!.env.example`
- Keep `.env.example` as placeholder-only template for dashboard setup.
- Preserve generated artifact hygiene by ignoring `__pycache__/` and `*.pyc`.
- Reset AGENTS guidance to non-ML core pipeline baseline and keep dashboard work isolated from runtime core flow changes.
