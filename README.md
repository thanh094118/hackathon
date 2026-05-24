# Web Log AI Detector

MVP CLI Pipeline for parsing Apache/Nginx/IIS access logs and detecting suspicious web requests using rule-based detection and simple AI/NLP techniques.

## Main Features

- Parse Apache, Nginx, and IIS access logs
- Normalize logs into a common schema
- Detect common web attacks:
  - SQL Injection
  - XSS
  - Path Traversal
  - Scanner activity
- Extract request features
- Apply AI/NLP-based detection
- Export alerts and reports
- Prepare output for SIEM integration

## MVP Usage

```bash
python main.py
```

Default paths:
- Input root: `input/` (auto-scan all `access*.log`)
- Output root: `outputs/`

## Conda Environment

Create the environment:

```bash
conda env create -f environment.yml
```

Activate it:

```bash
conda activate weblog-ai-detector
```

Or create manually:

```bash
conda create -n weblog-ai-detector python=3.11 -y
conda activate weblog-ai-detector
pip install -r requirements.txt
```

## Project Structure

```text
src/
├── collector/
├── parser/
├── normalizer/
├── preprocessor/
├── detection/
├── features/
├── models/
├── scoring/
├── reporting/
├── exporters/
└── utils/
```
