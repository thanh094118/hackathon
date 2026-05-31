# Decisions (2026-05-30)

- Alert notifications remain loosely coupled in `src/alerts/`; no parser, normalizer, detection, scoring, exporter, or main pipeline integration is implemented yet.
- Alert delivery must return `AlertSendResult` objects and isolate channel failures so one failed notifier does not crash or block other channels.
- Alert dry-run mode should not require real channel credentials and must avoid network calls.
- Real-time alert integration should go through `src/notifications/alerts.py`, which wraps `src.alerts`; raw Email, Telegram, and Slack delivery code must remain only in `src/alerts`.
- MongoDB exporter alert hooks should run only for the `incidents` collection to avoid duplicate notifications from all-request exports.
- Attack Simulator target-url mode must only allow localhost and hosts explicitly listed in `SIMULATOR_ALLOWED_HOSTS`.
- Dashboard-managed alert credentials are stored in MongoDB collection `alert_settings` under `_id: "default"`.
- Alert credential secrets must be encrypted with Fernet using `ALERT_SETTINGS_ENCRYPTION_KEY`; missing or invalid keys must not result in plaintext secret storage.
- Browser-facing alert settings responses must return secret status/masks only, never decrypted secret values.
- Runtime alert config loading should prefer MongoDB alert settings when available and fall back to environment variables for local/manual workflows.

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
- Bulk Upsert Command Size Mitigation:
  - Operations to MongoDB collections inside the exporter must be chunked (e.g. `chunk_size = 1000`) rather than sent in a single massive list. This prevents network socket drops, proxy resets, and payload limits (like MongoDB's 16MB limit).
- Keep this branch as Issue 3 frontend/dashboard-only; exclude backend, ML, data, infra, and unrelated test changes.
- Never track local `.env` in Git; enforce ignore rules with:
  - `.env`
  - `.env.*`
  - `!.env.example`
- Keep `.env.example` as placeholder-only template for dashboard setup.
- Preserve generated artifact hygiene by ignoring `__pycache__/` and `*.pyc`.
- Reset AGENTS guidance to non-ML core pipeline baseline and keep dashboard work isolated from runtime core flow changes.
- Mandatory sentence-transformers: enforce hard requirement for sentence-transformers and remove the fallback hashing trick.
- Robust IP Aggregation: aggregation queries grouping or matching on IP addresses must support both `$source_ip` and `$ip` using `$ifNull` array logic or `$or` matching to remain backward-compatible with normalized fields (`source_ip`) and fallback schemas.
- Advanced SOC Analytics Aggregations:
  - Timeline bucketing must group by both timestamp bucket and normalized attack type to support multi-series stacked/grouped visualization.
  - Blast Radius URI distribution query must compute percentages at the aggregation layer using `$unwind` on grouped results to minimize downstream transformation overhead.
  - Coordinated Campaign Detection (APT) parameters (min attacks, min attack types) should be completely configurable in the query arguments and UI.
- Stream Simulator Real-Time Timestamp Alignment:
  - During stream simulation, static CSV timestamps (from July 2020) are dynamically overridden at the producer-ingestion point with the current UTC system time (to the second) using the standard Apache access log format (`%d/%b/%Y:%H:%M:%S %z`).
  - This ensures that simulated requests match the wall-clock time at which they are actually processed, keeping them visible inside active real-time dashboard filter boundaries (e.g., "last 15 minutes", "last 24 hours") and allowing the charts to plot live scrolling data.
- Hybrid CQRS APT Campaign Detection:
  - Materialize APT attack campaigns into an `active_campaigns` collection using a MongoDB Atlas Scheduled Trigger running a JavaScript aggregation pipeline every 60 seconds with a `$merge` output stage.
  - Keep python-side dynamic queries in place to handle adjustable dynamic sliders (`min_attacks` and `min_attack_types`) in the UI campaigns table, satisfying both performance (for fast page loads / counts) and interactive flexibility requirements.


