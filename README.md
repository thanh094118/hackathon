# ThreatLens AI SOC Copilot

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

ThreatLens AI is a security operations platform for web-attack detection, threat investigation, and stateful alert management. It turns raw web server logs into actionable SOC intelligence with a hybrid pipeline that combines deterministic parsing, rule-based detection, feature engineering, machine learning, vector search, and stateful incident correlation.

The system is designed for Apache, Nginx, and IIS logs, and it can run either as a command-line pipeline or as a web dashboard backed by FastAPI and MongoDB Atlas.

---

## What This System Does

ThreatLens AI helps security teams:

- ingest raw access logs safely and normalize them into a unified schema
- detect suspicious web activity and predict attack behavior
- correlate related events into incidents to reduce alert fatigue
- explain why an event looks malicious using rules, patterns, and semantic similarity
- visualize attacker behavior, campaign activity, and baseline anomalies
- manage alert delivery credentials for Email, Telegram, and Slack

This is not just a log parser. It is a SOC copilot for web security operations.

---

## AI Model Design For Web Attack Prediction

The production ML layer is a **two-stage logistic-regression pipeline** built on handcrafted numeric features from the request preprocessor and feature extractor. The core predictor does **not** rely on n-gram classification in the main request-scoring path.

### Layer 1: Binary Attack Detection

The first model performs **binary classification** to decide whether a request is benign or attack-like. It uses the engineered feature vector generated from the normalized request, rather than raw text n-grams.

### Layer 2: Attack Type Classification

The second model performs **fine-grained attack type prediction**. Once a request is flagged as suspicious, the system classifies it into specific web attack families such as:

- SQL injection
- cross-site scripting
- path traversal
- command injection
- scanner / probing behavior
- other malicious web patterns supported by the trained model and rules

This two-layer approach gives the system both:

- **breadth**, by catching abnormal requests early
- **precision**, by labeling the attack type more accurately for analysts

---

## Core Capabilities

### 1. High-Throughput Log Ingestion

The ingestion pipeline reads log files safely in binary mode, handles mixed line endings, preserves malformed records, and merges only valid indented continuation lines. It supports single-file and batch processing.

### 2. Server-Aware Parsing

ThreatLens supports Apache, Nginx, and IIS logs. The parser auto-detects server type when not specified and preserves parser-domain error metadata for later analysis.

### 3. Request Normalization And Preprocessing

Parsed logs are normalized into a stable schema and then preprocessed for detection and model inference. This includes request decoding, whitespace normalization, and protection against common obfuscation tricks.

### 4. Hybrid Detection Engine

The detection layer combines:

- YAML-defined attack rules
- ML predictions
- handcrafted numeric features
- contextual scoring signals

This hybrid approach improves explainability and helps reduce false positives.

### 5. Stateful Incident Correlation

ThreatLens groups alerts into meaningful incidents instead of treating every suspicious request as a separate alert. The stateful alerting engine supports:

- sliding time-window grouping
- cooldown-based evidence merging
- severity-based escalation
- false-positive suppression
- incident lifecycle tracking

### 6. Baseline Analytics

The dashboard includes dynamic baselines and endpoint minimum floors to compare live behavior against expected traffic patterns. This helps distinguish true attacks from normal traffic bursts.

### 7. Explainable Threat Investigation

Analysts can inspect incident details, raw payloads, similar historical incidents, and remediation guidance. The system uses semantic similarity and vector search to provide context beyond a simple alert label.

### 8. Alert Credential Management

SOC teams can manage alert delivery settings directly from the dashboard. Supported channels include:

- Email
- Telegram
- Slack

Credentials are stored securely and can be tested from the UI.

---

## System Architecture

ThreatLens follows a multi-stage pipeline that turns raw web logs into structured intelligence for detection, correlation, and response.

<img src="asset/system%20architecture.png" alt="ThreatLens System Architecture" />

In practice, the platform is split into two operational paths:

- a **stateless ingestion path** for high-throughput log processing
- a **stateful intelligence path** for incident correlation, baselining, and alert management

The architecture is intentionally layered so that log ingestion, ML inference, rule matching, stateful alerting, and dashboard analytics can evolve independently without coupling the entire stack.

Within the `MLPredictor` module, the AI flow is also two-stage:

- `G --> H[ML Prediction Layer 1: Binary Attack Detection]`
- `H --> I[ML Prediction Layer 2: Attack Type Classification]`

This matches the architecture shown in `asset/system architecture.png` and keeps the README aligned with the visual design used in the presentation materials.

---

## MongoDB Architecture

MongoDB Atlas is the system's operational data backbone. It stores both the raw analytical records and the stateful security objects used by the dashboard and alerting engine.

<img src="asset/mongodb%20architecture.png" alt="ThreatLens MongoDB Architecture" />

### Core Collections And Their Roles

- `requests`: the main web-log intelligence store used for analytics, baselines, and campaign detection
- `incidents`: correlated incident records produced by the stateful alerting layer
- `managed_incidents`: analyst-managed incident feed used by the Threat Investigator UI
- `active_campaigns`: materialized campaign summaries for fast dashboard reads
- `attack_baselines`: hourly baseline thresholds used by the baseline analytics view
- `endpoint_min_floors`: minimum traffic floors per endpoint group
- `alert_settings`: encrypted alert delivery settings for Email, Telegram, and Slack
- `false_positives`: suppression history used to reduce repeated false alerts

### Why This Layer Matters

- It enables **fast dashboard reads** while still supporting **interactive analytical queries**
- It supports **stateful alerting**, including cooldown tracking and incident merging
- It keeps **baseline analytics** and **campaign detection** materialized for operational speed
- It centralizes **alert credential management** and preserves secrets with encryption

This database layout is a key part of the SOC workflow because it separates:

- raw detection data
- analyst-facing incident state
- precomputed analytics
- secured operational settings

---

## Dashboard Overview

The web dashboard is a single-page SOC console built with HTML, Tailwind CSS, Chart.js, and FastAPI.

### Command Center

The overview screen shows:

- total requests
- malicious requests
- total incidents
- active campaigns
- attack evolution over time
- attack type distribution
- top attacking IPs
- IP blast radius
- coordinated campaign detection

### Threat Investigator

The investigator view shows:

- correlated incidents
- raw security alerts
- incident metadata
- risk score and severity
- raw request payloads
- similar historical incidents
- AI vector analysis
- remediation actions

### Baseline Analytics

The baseline view shows:

- actual alerts vs baseline threshold
- endpoint minimum floors
- baseline recalculation controls

### Settings

The settings view lets analysts configure:

- global alerting
- dry-run mode
- alert channels
- dashboard URL
- SMTP settings
- Telegram settings
- Slack settings

---

## Screenshots

The repository includes presentation assets that show the main product UI and settings flow:

- Command Center: [docs/images/media__1780224525862.png](docs/images/media__1780224525862.png)
- Command Center, IP blast radius, campaign view: [docs/images/media__1780224538919.png](docs/images/media__1780224538919.png)
- Threat Investigator: [docs/images/media__1780224554815.png](docs/images/media__1780224554815.png)
- Similar incidents and remediation: [docs/images/media__1780224567909.png](docs/images/media__1780224567909.png)
- Alert Credentials settings: [docs/images/media__1780224576400.png](docs/images/media__1780224576400.png)

---

## Repository Structure

```text
├── src/
│   ├── collector/          # Safe log ingestion and logical record grouping
│   ├── parser/             # Apache / Nginx / IIS parsers and server detection
│   ├── normalizer/         # Stable schema normalization
│   ├── preprocessor/       # Request decoding and sanitization
│   ├── detection/          # YAML rule engine
│   ├── features/           # Numeric feature extraction
│   ├── scoring/            # Risk scoring and MongoDB query helpers
│   ├── alerts/             # Stateful alerting and channel dispatch
│   ├── dashboard/          # FastAPI backend and static dashboard
│   ├── exporters/          # JSONL / CSV / MongoDB export helpers
│   └── main.py             # Pipeline entry point
├── docs/                   # Product documents, slides, and screenshots
├── outputs/                # Generated artifacts
└── tests/                  # Automated tests
```

---

## Getting Started

### Prerequisites

- Python 3.8+
- MongoDB Atlas or a local MongoDB instance for full dashboard functionality

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run The Pipeline

Process a single log file:

```bash
python -m src.main --input data/raw/apache/access.log --server-type apache --output-dir outputs/my_run
```

Process a batch or a directory of logs:

```bash
python -m src.main --input data/raw --output-dir outputs/batch_run
```

### Run The Dashboard

```bash
python -m src.dashboard.server
```

Open the dashboard at:

```text
http://127.0.0.1:8501
```

### Demo Mode

If you want to run the dashboard without MongoDB Atlas, enable mock mode:

```bash
DASHBOARD_USE_MOCK=1 python -m src.dashboard.server
```

---

## Operational Data And Optional Debug Output

ThreatLens is designed as a MongoDB-backed end-to-end system. In the normal operational flow, the primary runtime data lives in Atlas collections rather than in local project artifacts.

### MongoDB Collections Used In The Main Flow

- `requests`
- `incidents`
- `managed_incidents`
- `active_campaigns`
- `attack_baselines`
- `endpoint_min_floors`
- `alert_settings`
- `false_positives`
- `pipeline_runs`

### Optional Local Debug Export

If you need offline inspection or stage-level debugging, the pipeline can still export local artifacts with `--debug-local`. In that mode, it writes the familiar stage outputs under `outputs/`:

- `collector_results/*_raw_lines.jsonl`
- `parser_results/*_parsed_logs.jsonl`
- `normalizer_results/*_normalized_logs.jsonl|csv`
- `preprocessor_results/*_preprocessed_requests.jsonl`
- `detector_results/*_alerts.jsonl|csv`
- `feature_results/*_features.csv`
- `report/*_report.md`
- `report/*_run_summary.json`

---

## Key Design Principles

1. **Explainability first**  
   ThreatLens combines rules, features, and semantic context so analysts can understand why a request was flagged.

2. **Stateful over stateless**  
   The system reduces alert fatigue by grouping related events into incidents and preserving investigation context.

3. **Hybrid intelligence**  
   Detection is driven by both deterministic rules and AI-based prediction for better coverage and precision.

4. **Operational safety**  
   The ingestion layer is defensive by design, with careful handling of encodings, line endings, and evasive payloads.

5. **Dashboard-driven SOC workflow**  
   The UI is designed for day-to-day analyst operations: triage, investigation, baselining, and alert configuration.

---

## Testing

Run the test suite:

```bash
pytest -q tests
```

Run parser-focused tests:

```bash
pytest -q tests/test_parser.py
```

Run collector-focused tests:

```bash
pytest -q tests/test_collector.py
```

---

## Notes

- The dashboard can operate in mock mode when MongoDB is unavailable.
- The alert settings UI stores secrets securely and only exposes masked/public status values.
- The platform is intended for SOC operations on web application traffic and log-driven threat detection.
