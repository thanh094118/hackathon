# Web Server Log Parser + Rule-Based Attack Detection

This project is a non-ML cybersecurity pipeline for parsing web access logs and detecting suspicious requests with YAML rules plus hand-crafted features.

Current phase scope:
- Included: collector, parser, normalizer, request preprocessor, rule detector, feature extraction, risk scoring, exporting, markdown reporting.
- Not included yet: AI/NLP or ML training/detection (TF-IDF, Logistic Regression, SVM, Isolation Forest, deep learning, vector search).

## Environment

Conda:

```bash
conda env create -f environment.yml
conda activate vdt
```

Pip:

```bash
pip install -r requirements.txt
```

## Run The Pipeline

Expected CLI:

```bash
python -m src.main --input data/raw/apache/access.log --server-type apache --output-dir outputs/apache_run
```

With explicit rules file:

```bash
python -m src.main --input input/Apache/access1.log --server-type apache --output-dir outputs/apache_run --rules data/labels/attack_patterns.yaml
```

## Required Arguments

- `--input`: path to one access log file
- `--server-type`: `apache`, `nginx`, or `iis`
- `--output-dir`: output directory for one run
- `--rules` (optional): YAML rule file path (default: `data/labels/attack_patterns.yaml`)

## Output Files

One run writes these artifacts into `--output-dir`:

- `raw_lines.jsonl`
- `parsed_logs.jsonl`
- `normalized_logs.jsonl`
- `normalized_logs.csv`
- `preprocessed_requests.jsonl`
- `features.csv`
- `alerts.jsonl`
- `alerts.csv`
- `report.md`
- `run_summary.json`

## Tests

Run all tests:

```bash
pytest -q
```

Cache-free run:

```bash
PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider
```
