# Issues Assignment: Feature Context Enrichment & Task Division

This document outlines the task division and enriched technical contexts for the new features to be implemented in this repository. The tasks are distributed among **Hùng** (AI & Vector Search), **Vinh** (Advanced MongoDB Aggregation Pipelines), and **Thanh** (Automation, Alerts, & Simulation).

---

## 🧑‍💻 Task Assignment Matrix

| Owner | Feature Category | Features / Modules | Difficulty | Target Files |
| :--- | :--- | :--- | :---: | :--- |
| **Hùng** | **Vector Search & AI Threat Explainer** | **Feature 1**: Semantic "Similar Incident" Explorer<br>**Feature 2**: AI Threat Explainer (CAPEC/MITRE Mapping) | Medium | `src/scoring/mongodb_queries.py`<br>`src/dashboard/query_adapter.py`<br>`src/dashboard/investigator_tab.py` |
| **Vinh** | **Aggregation & SOC Analytics** | **Feature 3**: Coordinated Campaign Detection (APT)<br>**Feature 4**: Real-time Blast Radius Pie Chart<br>**Feature 5**: Time-series Attack Evolution Stacked Bar Chart | High | `src/scoring/mongodb_queries.py`<br>`src/dashboard/query_adapter.py`<br>`src/dashboard/overview_tab.py` |
| **Thanh** | **Alerts Notification** | **Ticket 3**: Real-time Alerts (Email & Telegram Bot) | Medium | `src/notifications/alerts.py` (NEW)<br>`src/main.py`<br>`src/exporters/mongodb_exporter.py` |
| **Thanh** | **Simulation** | **Ticket 4**: CLI Multi-Stage Campaign Simulator | Medium | `scripts/simulate_attacks.py` (NEW)<br>`scripts/simulate_stream.py` (OR Ingestion pipe) |

---

## 🎫 Ticket 1: Semantic "Similar Incident" Explorer & AI Explainer (Hùng)

### Problem Statement
1. **Semantic Explorer (Feature 1)**: Traditional regex or keyword searches miss obfuscated/transformed payloads (e.g. `GET /?q=%3Csvg%2Fonload%3Dalert%281%29%3E` vs `GET /search?val=<script>alert(1)</script>`). Analysts need a way to inspect the vector database to find requests with similar semantic meanings.
2. **AI Explainer (Feature 2)**: ML model classification results (e.g. "Malicious 98%") need a plain-English explanation of *why* it was flagged, mapping it to a security knowledge base (CAPEC/MITRE).

### Implementation Plan
1. **Collection Mapping & Verification:**
   - Verify that `scripts/setup_mongodb.py` has run successfully to establish the `vector_index` (using `SentenceTransformer` with 384 dimensions and cosine similarity) on the `requests` (or `unified_logs`) and `attack_patterns` collections.
2. **Backend Queries (`src/scoring/mongodb_queries.py`):**
   - Verify `find_similar_logs(collection, query_vector, limit, filter_dict)` is working. It must execute a `$vectorSearch` query stage against the requests collection.
   - Refine `explain_threat_via_vector_search(...)` to fetch the top pattern match, its description, capec/mitre references, examples, and remediation.
3. **Bridge via Query Adapter (`src/dashboard/query_adapter.py`):**
   - Implement `find_similar_requests(self, request_embedding: List[float], limit: int = 5) -> List[Dict[str, Any]]`.
   - Add robust mock fallbacks (utilizing `self._mock["requests"]`) for this method to keep the dashboard functional under `DASHBOARD_USE_MOCK=1`.
4. **UI Integration (`src/dashboard/investigator_tab.py`):**
   - In `render_investigator_tab`, add a **"Find Similar Incidents"** button under the selected incident detail layout.
   - On click, execute `find_similar_requests` and render a table showing: Timestamp, Attacker IP, Method, URI, Risk Score, and Match Score (Similarity % derived from `vectorSearchScore`).
   - Format the Vector Search Explanation card to clearly display the name, CAPEC code (e.g. `CAPEC-66`), MITRE technique (e.g. `T1505`), description, and recommendations dynamically.

---

## 🎫 Ticket 2: MongoDB Aggregation Pipelines for Analytics (Vinh)

### Problem Statement
1. **Coordinated Campaign Detection (Feature 3)**: Isolated scanning or probes are common, but when a single IP triggers multiple attack types (e.g. SQLi, XSS, Path Traversal) and high request volume, it represents an active APT campaign.
2. **Real-time Blast Radius (Feature 4)**: Once an attacking IP is identified, analysts need to know which endpoints/URIs it targeted and the percentage distribution of the requests.
3. **Time-series Attack Evolution (Feature 5)**: Attacks evolve chronologically (e.g., Nikto scanner reconnaissance first, SQLi database probes second, and Traversal file exfiltration third).

### Implementation Plan
1. **Coordinated Campaign Aggregation (`src/scoring/mongodb_queries.py`):**
   - Refine `detect_attack_campaigns(db, min_attacks, limit, ...)`:
     - Stage 1: `$match` logs utilizing `_malicious_match_query()`.
     - Stage 2: `$group` by `$source_ip` (supporting schema fallbacks to `$ip` using `$ifNull`).
     - Stage 3: `$addToSet` to collect all unique `attack_type` occurrences and target `uri` values.
     - Stage 4: `$addFields` for `attack_type_count: {"$size": "$attack_types"}`.
     - Stage 5: `$match` where `total_attacks` > 50 and `attack_type_count` >= 3 (representing APT campaign profile).
2. **Real-time Blast Radius (`src/scoring/mongodb_queries.py`):**
   - Implement `get_ip_blast_radius(db, ip)`:
     - `$match` on the specific IP.
     - `$facet` or sequential `$group` pipeline to compute:
       - URI request counts (`$group` by `$uri` with count).
       - Total request count.
     - `$project` to calculate the percentage (`{"$multiply": [{"$divide": ["$uri_count", "$total_count"]}, 100]}`).
   - Hook this into `src/dashboard/query_adapter.py`.
   - Under `src/dashboard/overview_tab.py`, display an interactive panel. When clicking on an IP in the campaigns or top attacking IPs list, render a Plotly donut chart depicting its Blast Radius.
3. **Attack Evolution Timeline (`src/scoring/mongodb_queries.py`):**
   - Implement `generate_attack_timeline(db, ...)` with tactics breakdown:
     - `$match` malicious logs.
     - `$addFields` to convert string timestamps into dates.
     - `$group` using `$dateTrunc` (with 5-minute or 1-hour intervals) AND `$attack_type` as a compound group key `_id: {time: "$truncated_time", type: "$attack_type"}`.
     - `$sort` by time.
   - Hook into the query adapter. In `src/dashboard/overview_tab.py`, render a Plotly stacked bar chart representing time buckets on the X-axis, count on the Y-axis, and colored stacked segments representing different attack types (e.g. scanning, SQLi, traversal).

---

## 🎫 Ticket 3: Real-Time Alerts Notification Module (Thanh)

### Problem Statement
The system should alert the security team immediately when critical threats (risk score >= 80) are detected, without forcing them to sit in front of the dashboard.

### Implementation Plan
1. **Alert Notifications Module (`src/notifications/alerts.py`):**
   - Create `src/notifications/alerts.py` containing `AlertDispatcher`.
   - Implement SMTP email alerts (`smtplib` + `MIMEText`).
   - Implement Telegram Bot alerts (`requests.post` to `https://api.telegram.org/bot<TOKEN>/sendMessage`).
   - Support `.env` variables: `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `SMTP_SERVER`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `ALERT_RECEIVER_EMAIL`.
2. **Integration into Export Pipeline:**
   - Hook `AlertDispatcher` into `src/exporters/mongodb_exporter.py`'s `export` function, checking if the record's `risk_score >= 80` or `should_alert == True`.
   - If yes, trigger alerts asynchronously (using Python's `threading` or `asyncio` to avoid blocking pipeline execution).

---

## 🎫 Ticket 4: Automated CLI Attack & Campaign Simulator (Thanh)

### Problem Statement
To evaluate the SOC Copilot, we need a way to generate simulated attacks. The target environment should normally show normal background traffic (or a few sporadic abnormal requests). When triggered, the simulator should generate a multi-stage attack campaign that injects logs into the detection pipeline to verify real-time ingestion, campaign correlation, and alert generation.

### Implementation Plan
1. **CLI Attack Simulator Script (`scripts/simulate_attacks.py`):**
   - Create a standalone Python CLI script `scripts/simulate_attacks.py`.
   - Implement two main modes:
     - `--mode single`: Sends isolated attacks (e.g. single SQLi or XSS scan).
     - `--mode campaign`: Simulates a full multi-stage APT attack campaign from a single source IP.
2. **APT Campaign Simulation Sequence:**
   - When `--mode campaign` is triggered, the script executes a sequence of attacks over a short window:
     - **Stage 1 (Recon/Scanning)**: Sends 20+ directory scanning requests (User-Agent: Nikto/Sqlmap, triggers `scanner` type) targeting various assets.
     - **Stage 2 (Exploitation - SQL Injection)**: Sends 20+ SQLi requests (e.g., `UNION SELECT`, `' OR 1=1 --`) targeting login/search endpoints.
     - **Stage 3 (Exfiltration - Path Traversal)**: Sends 20+ traversal requests (e.g., `../../etc/passwd`) targeting file download/view endpoints.
3. **Log Ingestion/Injection Mechanism:**
   - Implement options for injection:
     - `--target-url`: Sends HTTP requests with signature payloads directly to a target web server (so standard logs are captured by the streaming collector).
     - `--direct-pipe`: Writes the generated raw log lines directly into the temporary directory/queue read by the active `scripts/simulate_stream.py` consumer, ensuring immediate pipeline parsing, vector scoring, and alerts creation.
