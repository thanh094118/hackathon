# Current Status (2026-05-30)

- **Loose-Coupled Alert Notifications (2026-05-31)**:
  - Added standalone `src/alerts/` package for reusable Email, Telegram, and Slack alert delivery.
  - Implemented flexible `AlertEvent.from_incident(...)`, structured `AlertSendResult`, environment-backed `AlertConfig`, dry-run support, safe missing-credential handling, and dispatcher-level failure isolation.
  - Added placeholder-only `.env.example` alert settings; local `.env` was not modified.
  - Verified with `python -m compileall src` and `pytest -q tests/test_alerts.py`.
  - Removed generated Python cache directories under `src/` and `tests/` after verification.

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
