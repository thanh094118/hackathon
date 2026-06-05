# Current Status (2026-06-06)

- **Merge Conflict Resolution & Simulator Test Fix (2026-06-06)**:
  - Reconciled Git merge conflicts in `src/dashboard/query_adapter.py` resulting from diverging branches (Schema V2 consolidation vs. remote updates).
  - Fixed a broken test case (`test_cli_argument_parsing`) in `tests/test_attack_simulator.py` where CLI parameters expected by the test did not match the newly refactored parser (`build_parser`) in `scripts/simulate_attacks.py`.
  - Staged all changes and finalized the merge commit successfully.
  - Verification:
    - Run the entire test suite `python -m pytest tests -q` successfully passing all 313 test cases.

- **Dashboard Overview Malicious Count Fix (2026-06-06)**:
  - Fixed `Malicious Requests = 0` in the static dashboard overview.
  - Root cause: `src/dashboard/query_adapter.py` overview summary still used legacy flat-field MongoDB match conditions (`prediction.label`, `should_alert`, `risk_score`) while live data is stored under nested Schema V2 fields (`detection.ml.*`, `scoring.*`).
  - Updated malicious/high-severity summary match queries to recognize nested schema fields while keeping legacy flat fallbacks.
  - Added regression coverage in [tests/test_dashboard_query_adapter.py](file:///d:/Code/test/hackathon/tests/test_dashboard_query_adapter.py) asserting live summary queries include nested `detection.ml.*` and `scoring.*` paths.
  - Verification:
    - `/home/thanh/miniconda3/envs/easymocap/bin/python -m pytest -q tests/test_dashboard_query_adapter.py tests/test_dashboard_api.py` passed: 51 tests.
    - Live check via `DashboardQueryAdapter(use_mock=False).get_soc_summary("24h")` now returns non-zero malicious counts (`malicious_requests: 5694`) and high-severity counts (`high_severity_incidents: 4490`) against the connected MongoDB dataset.

- **Static Dashboard Managed-Incident Route Regression Fix (2026-06-05)**:
  - Diagnosed `GET /api/incidents/managed?limit=100` returning `404` on the FastAPI-served static dashboard.
  - Root cause: `src/dashboard/api.py` declared dynamic route `GET /api/incidents/{incident_id}` before the specific managed-feed route, so FastAPI matched `"managed"` as an `incident_id`.
  - Fixed by moving `GET /api/incidents/managed` above the dynamic detail route.
  - Added regression coverage in [tests/test_dashboard_api.py](file:///d:/Code/test/hackathon/tests/test_dashboard_api.py) to ensure the managed feed endpoint is not shadowed again.
  - Verification:
    - `/home/thanh/miniconda3/envs/easymocap/bin/python -m pytest -q tests/test_dashboard_api.py -q` passed.

- **Static Dashboard: Stateful Alerting + Baseline Analytics UI (2026-06-05)**:
  - Extended [src/dashboard/api.py](file:///d:/Code/test/hackathon/src/dashboard/api.py) with shared baseline snapshot helpers, richer `GET /api/baseline/status` payloads (`endpoint_floors`, `comparison_last_24h`, `generated_at`), and new `POST /api/baseline/recalculate`.
  - Added `get_baseline_comparison_last_24h(...)` to [src/scoring/mongodb_queries.py](file:///d:/Code/test/hackathon/src/scoring/mongodb_queries.py) to aggregate 24 hourly actual-vs-threshold comparison points from `requests` + `attack_baselines`.
  - Updated [src/dashboard/static/index.html](file:///d:/Code/test/hackathon/src/dashboard/static/index.html) to add:
    - `Baseline Analytics` navigation and workspace.
    - Stateful `Correlated Incidents` vs `Raw Security Alerts` mode switch in Threat Investigator.
    - Managed incident detail rendering from `/api/incidents/managed`.
    - `Mark as False Positive` action for managed incidents only, with immediate local UI suppression update.
  - Extended [tests/test_dashboard_api.py](file:///d:/Code/test/hackathon/tests/test_dashboard_api.py) with coverage for:
    - baseline status enriched payload
    - lazy baseline/floor materialization
    - manual baseline recalculation
    - false-positive success/failure flows
  - Verification:
    - `python -m compileall src` passed.
    - `/home/thanh/miniconda3/envs/easymocap/bin/python -m pytest -q tests/test_dashboard_api.py tests/test_smart_alerting.py` passed: 35 tests.
    - Browser/manual visual verification of the updated static dashboard was not run in this session.

- **MongoDB Schema Restructuring (Flat to Nested Schema Version 2)**:
  - Restructured flat database structures into logical nested sub-documents (`request`, `preprocessed`, `features`, `detection`, `scoring`) to align with production best practices.
  - Implemented schema definitions, conversion mapping, and validation helpers in [src/schemas/mongodb_schema.py](file:///d:/Code/test/hackathon/src/schemas/mongodb_schema.py) and [src/schemas/field_mapping.py](file:///d:/Code/test/hackathon/src/schemas/field_mapping.py).
  - Created and ran an offline in-place migration script [scripts/migrate_collections.py](file:///d:/Code/test/hackathon/scripts/migrate_collections.py), successfully updating 28,492 `requests` documents and 15,403 `incidents` documents in the MongoDB Atlas cluster.
  - Modified [src/exporters/mongodb_exporter.py](file:///d:/Code/test/hackathon/src/exporters/mongodb_exporter.py) and [src/main.py](file:///d:/Code/test/hackathon/src/main.py) to export newly processed records in the clean Version 2 nested format.
  - Updated aggregation queries in [src/scoring/mongodb_queries.py](file:///d:/Code/test/hackathon/src/scoring/mongodb_queries.py) to query the clean nested schema directly.
  - Updated [src/dashboard/query_adapter.py](file:///d:/Code/test/hackathon/src/dashboard/query_adapter.py) to query and parse the nested schema directly without flat fallback.
  - Verified with comprehensive unit/integration tests (`tests/test_schema_integration.py` etc.). All 294 tests passed successfully.

- **Alert Credential Settings Planning (2026-05-31)**:
  - Inspected `src/dashboard/server.py`, `src/dashboard/api.py`, `src/dashboard/static/index.html`, and `src/alerts/config.py` / `dispatcher.py`.
  - Confirmed alert credentials are currently environment-backed only, while the dashboard has FastAPI endpoints and static hash-routed views for Overview and Threat Investigator.
  - Added `conversation_cache/alert_settings_plan.md` with a concrete plan for a Settings section, MongoDB `alert_settings` document, Fernet encryption for secrets, masked browser responses, env fallback, API endpoints, UI changes, and focused tests.
  - Updated `conversation_cache/todo.md` with the implementation checklist.

- **Alert Credential Settings Implementation (2026-05-31)**:
  - Added `src/alerts/crypto.py` with Fernet-based secret encryption/decryption using `ALERT_SETTINGS_ENCRYPTION_KEY`.
  - Added `src/alerts/settings_store.py` for MongoDB-backed `alert_settings` persistence, public masked settings, secret-preserving updates, and conversion into `AlertConfig`.
  - Added `load_effective_alert_config(...)` in `src/alerts/config.py` and wired `build_default_dispatcher()` to prefer MongoDB settings with env fallback.
  - Added dashboard API endpoints:
    - `GET /api/settings/alerts`
    - `PUT /api/settings/alerts`
    - `POST /api/settings/alerts/test`
  - Added a Settings navigation item and Alert Credentials form in `src/dashboard/static/index.html`.
  - Added placeholder `ALERT_SETTINGS_ENCRYPTION_KEY` to `.env.example` and `cryptography` to `requirements.txt`.
  - Added tests in `tests/test_alert_settings_store.py` and dashboard API coverage in `tests/test_dashboard_api.py`.
  - Verification:
    - `python -m compileall src` passed.
    - Initial pytest run without `PYTHONPATH=.` failed with `ModuleNotFoundError: No module named 'src'` in this interpreter.
    - `$env:PYTHONPATH='.'; pytest -q tests/test_alerts.py tests/test_alert_settings_store.py tests/test_dashboard_api.py` passed: 31 tests.
    - Generated `__pycache__` directories from compile/test were removed.

- **Alert Settings Error Diagnostics Fix (2026-05-31)**:
  - Investigated browser errors:
    - `Alert settings have not been saved` occurs because the test endpoint requires a successfully saved MongoDB settings document first.
    - `ALERT_SETTINGS_ENCRYPTION_KEY is invalid` occurs when the env value is not a valid Fernet key, commonly because the placeholder from `.env.example` was copied literally.
  - Added encryption key status reporting to public alert settings payloads without exposing the key.
  - Improved save/test API error details with a valid Fernet key generation command.
  - Updated the Settings UI to display encryption key status and show backend error details in toast messages.
  - Added tests for encryption status and invalid-key API errors.
  - Verification:
    - `python -m compileall src` passed.
    - `$env:PYTHONPATH='.'; pytest -q tests/test_alert_settings_store.py tests/test_dashboard_api.py` passed: 22 tests.
    - Generated `__pycache__` directories from compile/test were removed.

- **Telegram/Slack Alert Failure Diagnostics (2026-05-31)**:
  - Investigated user-visible test result where Telegram returned only `error: "HTTPError"`.
  - Updated `src/alerts/telegram_notifier.py` to preserve safe HTTP status and Telegram API response details, e.g. `HTTP 400: Bad Request: chat not found`.
  - Updated `src/alerts/slack_notifier.py` similarly for HTTP status/body diagnostics.
  - Updated dashboard Settings test-alert toast so failed channel results show channel-specific error details instead of treating HTTP 200 API responses with failed channel results as success.
  - Added regression coverage in `tests/test_alerts.py` for Telegram HTTP error detail extraction.
  - Verification:
    - `python -m compileall src` passed.
    - `$env:PYTHONPATH='.'; pytest -q tests/test_alerts.py tests/test_dashboard_api.py` passed: 29 tests.
    - Generated `__pycache__` directories from compile/test were removed.

- **Loose-Coupled Alert Notifications (2026-05-31)**:
  - Added standalone `src/alerts/` package for reusable Email, Telegram, and Slack alert delivery.
  - Implemented flexible `AlertEvent.from_incident(...)`, structured `AlertSendResult`, environment-backed `AlertConfig`, dry-run support, safe missing-credential handling, and dispatcher-level failure isolation.
  - Added placeholder-only `.env.example` alert settings; local `.env` was not modified.
  - Verified with `python -m compileall src` and `pytest -q tests/test_alerts.py`.
  - Removed generated Python cache directories under `src/` and `tests/` after verification.
  - Added `scripts/test_alerts_manual.py` for safe manual dry-run testing of Email, Telegram, and Slack alert dispatch.

- **Real-Time Alerts & Attack Simulator (2026-05-31)**:
  - Added `src/notifications/alerts.py` wrapper that reuses `src.alerts` for high-risk incident alerting.
  - Integrated alert dispatch into `MongoDBExporter` only for exported `incidents` records, with safe failure logging.
  - Added shared simulator engine and payloads under `src/simulator/`.
  - Added Streamlit Attack Simulator tab and dashboard navigation entry.
  - Added CLI simulator at `scripts/simulate_attacks.py`.
  - Added tests for notification wrapper and simulator behavior.
  - Removed `.env` and `.env.template` from Git tracking; `.env.template` local content was sanitized to placeholders.
  - Verified with `python -m compileall src`, `pytest -q tests/test_notifications_wrapper.py tests/test_attack_simulator.py`, and `pytest -q tests/test_alerts.py`.

- **MongoDB Exporter Chunking**:
  - Implemented command chunking in `src/exporters/mongodb_exporter.py` with `chunk_size = 1000`.
  - This successfully prevents TCP socket timeouts and connection closed errors on large bulk writes.

- **Mandatory sentence-transformers**:
  - Made `sentence-transformers` a hard requirement in `src/features/embedding_engine.py` and removed the fallback hashing logic.

- **Real Log Ingestion**:
  - Ingested 8,000 log records from the real `converted_data_capec_multilabel_part001_copy_sample.log` dataset containing live SQLi and XSS attacks.
  - Successfully seeded 16 attack patterns and stored 8,000 scored logs, 2,730 incidents, and 1 pipeline run summary in MongoDB Atlas.

- **Dashboard Verification**:
  - Successfully started the Streamlit dashboard on local port `8501`.
  - Verified the MongoDB Atlas connection status is green (**Connected**).
  - Verified the **SOC Overview** tab exhibits correct live statistics from the 8,000 ingested records.
  - Verified the **Threat Investigator** tab displays real incidents and performs Atlas Vector Search successfully against the seeded attack patterns.

- **Top Attacking IPs Fix**:
  - Fixed schema mismatch in `src/scoring/mongodb_queries.py` (`get_top_attacking_ips`, `detect_attack_campaigns`, and `generate_attack_timeline`) where IP groupings were referencing `$ip` instead of `$source_ip` from the normalized log schema.
  - Configured a multi-field `$ifNull` fallback checking `["$source_ip", "$ip", "Unknown"]` to ensure compatibility across schemas.
  - Verified that the SOC Dashboard now correctly aggregates and displays the attacker IP address `172.26.0.1` and other source IPs instead of "Unknown".

- **Sidebar Detection Filter & Vector Search Fixes**:
  - Implemented a **Detection Method** filter in the Threat Investigator sidebar allowing the user to select: All, Rules Only, ML Only, or Hybrid Only. This dynamically filters matching incidents in the Threat Explorer.
  - Upgraded pattern normalization in `_normalize_pattern` in `src/dashboard/query_adapter.py` to correctly map database-specific seeded fields (`category`, `payload_example`, `mitigation`) to the dashboard expectations (`attack_type`, `examples`, `remediation`).
  - Verified that Vector Search Match Cards now display actual threat categories (e.g. `Type: scanner` or `Type: sqli`) and valid MITRE references (e.g. `MITRE: T1595 | T1505`) instead of displaying "Unknown" or "N/A".

- **Issue 2: Advanced Aggregation Pipelines for SOC Analytics**:
  - **Coordinated Campaign Detection (APT)**: Updated campaign detection aggregation logic to match and filter on multi-tactic profiles (size of attack type set >= 3) and high frequency (total_attacks >= 50). Added slider inputs in the dashboard to make these thresholds fully configurable by the SOC analyst.
  - **Real-time Blast Radius**: Implemented `get_ip_blast_radius` aggregation to calculate the distribution and percentage of target URIs hit by any given attacker IP. Exposed this interactively in the "Top Attacking IPs" section via a dropdown that triggers a Plotly donut chart visualization.
  - **Time-series Attack Evolution**: Redesigned `generate_attack_timeline` to support grouping by both truncated timestamp (`$dateTrunc` by minute/hour/day) and normalized attack type. Replaced the simple line chart with a Plotly stacked bar chart on the dashboard to visualize how attacker methods shift over time (e.g., from scanning to SQL injection).
  - **Unit Test Coverage**: Wrote comprehensive unit tests in both `tests/test_mongodb_integration.py` and `tests/test_dashboard_query_adapter.py` covering both mock mode and live/patched pipeline aggregation queries. Verified all tests pass.

- **ThreatLens AI Ultimate Next.js Frontend Specification**:
  - Generated `threatlens_ai_ultimate_frontend_spec.md` with complete layouts, Tailwind styles, interactive Recharts configurations, data schemas, API routes, and TSX component implementations matching the user's cyberpunk design assets.

- **Stream Simulator Real-Time Timestamp Processing**:
  - Fixed a NameError bug in `scripts/simulate_stream.py` where `tmp_path` was referenced without being defined. Refactored the consumer batch file writing to use `tempfile.NamedTemporaryFile` and added a robust `finally` cleanup block.
  - Implemented dynamic real-time timestamp simulation in `Producer._read_csv`. It now rewrites the static 2020 timestamps from the raw CAPEC CSV to the current wall-clock UTC time (formatted in standard Apache access log format) at the moment of queuing.
  - This ensures that simulated requests match the current timeline, enabling correct filtering and rendering in real-time dashboards (e.g. "last 15 minutes" filters).
  - Wrote a new unit test suite `tests/test_stream_simulator.py` to verify the timestamp override logic. Verified all 228 test cases across the codebase pass successfully.

- **Dashboard Dynamic Timeframe Dropdown (SIEM-like behavior)**:
  - Added support for dynamic timeframe selection dropdown at the top of the dashboard containing options: Last 15 Minutes (`15m`), Last Hour (`1h`), Last 24 Hours (`24h`), Last 7 Days (`7d`), and All Time (`all`).
  - Updated all REST endpoints, MongoDB query wrappers, and the frontend JS API fetch layer to seamlessly propagate this parameter, updating charts and count cards in real time.
  - Verified that changing the dropdown correctly filters out mock/live database queries to match target time ranges.
  - Verified that all unit tests and API integration tests pass with 100% success.
  - Visual rendering and interaction validated successfully via browser subagent.

- **Hybrid CQRS APT Campaign Detection (Atlas Materialized Views)**:
  - Upgraded the APT Campaign Detection system to a CQRS Hybrid architecture.
  - Dynamic queries for interactive thresholds and sliders are kept on the Python backend (`detect_attack_campaigns`) to support live SOC analyst customization.
  - Implemented background pre-computation using a MongoDB Atlas Scheduled Trigger running a JavaScript aggregation pipeline every 60 seconds, materializing the results into `active_campaigns` using the `$merge` operator.
  - The dashboard dual-reads: overview count cards read from the fast `active_campaigns` collection (including a dynamic freshness timestamp/badge indicating the last materialization time), while the interactive campaigns table reads dynamically.
  - Created new unit tests and REST endpoints (/api/materialized-campaigns) to verify the dual-path reads. Verified all test suites pass with 100% success.

- **Stateful Intelligent Alerting System (2026-05-31)**:
  - Implemented Contextual Correlation Engine in `src/alerts/correlation_engine.py` grouping alerts by IP + time window + behavioral classifications (reconnaissance, brute_force, multi_vector).
  - Implemented Stateful Incident Manager in `src/alerts/incident_manager.py` with cooldown period and evidence merging.
  - Implemented Dynamic Anomaly Baseline in `src/alerts/dynamic_baseline.py` comparing counts against standard deviation offsets (3-sigma).
  - Implemented FP Suppression Engine in `src/alerts/fp_suppression.py` matching new incidents against `false_positives` collection using Atlas Vector Search.
  - Centralized baseline/FP search queries in `src/scoring/mongodb_queries.py`.
  - Added new REST endpoints: `GET /api/incidents/managed`, `POST /api/incidents/{incident_id}/false-positive`, and `GET /api/baseline/status`.
  - Wrote a comprehensive unit/integration test suite at `tests/test_smart_alerting.py` verifying all 4 engines and batch flow.
  - Verified that all 300 tests pass successfully.

- **Intelligent Alerting Enhancements (2026-05-31)**:
  - **Severity Override during Cooldown**: Updated the Incident Manager to break active cooldowns and trigger immediate alerts if an incoming event's severity exceeds the active incident's current severity.
  - **Endpoint-Group Specific Baselines & Min Floors**: Replaced the global minimum floor with dynamic, endpoint-group specific floors. Segmented paths into `sensitive`, `api`, `default`, and `root` groups, automatically projecting them in MongoDB via aggregation pipelines (computing 90th percentile scaled floors) and resolving them in memory.
  - **Smokescreen Protection (Contextual Risk Separation)**: Implemented priority risk scoring in `CorrelationEngine` and `IncidentManager`. If an incident contains requests targeting different endpoint groups, its risk score and severity are determined solely by the most sensitive group present, preventing attackers from diluting high-severity threats on sensitive resources using low-severity volume/noise on static/root resources.
  - **Verification**: Added 5 new tests to `tests/test_smart_alerting.py` (covering grouping, endpoint floors, smokescreen protection, and merge recalculation). All 309 repository tests passed.

- **Dashboard Malicious Requests Statistics Fix (2026-05-31)**:
  - Identified that the dashboard displayed `0` Malicious Requests because `DashboardQueryAdapter._malicious_match_query()` checked only Schema Version 1 (flat) fields, whereas the database collections were migrated to Schema Version 2 (nested).
  - Modified `_malicious_match_query()` in [src/dashboard/query_adapter.py](file:///d:/Code/test/hackathon/src/dashboard/query_adapter.py) to support both nested and flat fields.
  - Modified `get_soc_summary()` in `src/dashboard/query_adapter.py` to correctly query nested severity (`detection.rules.severity`) and risk score (`scoring.risk_score`) fields.
  - Updated projections in fallback query wrappers (`get_attack_type_distribution`, `get_top_attacking_ips`, `get_attack_timeline`) to request nested sub-documents `detection` and `scoring`, enabling downstream functions to read these values correctly.
  - Verified that `get_soc_summary` now reports correct counts of malicious requests (e.g. `18549` instead of `0`) and high severity incidents.
  - Verified all 309 unit and integration tests continue to pass.
