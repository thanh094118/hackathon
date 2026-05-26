# Web Attack Detection Report

- Generated at (UTC): `2026-05-26T06:17:26.812519+00:00`
- Input file: `data/raw/apache/access.log`
- Server type: `apache`
- Rules file: `data/labels/attack_patterns.yaml`
- Output dir: `outputs/apache_run`

## Pipeline Summary

- Raw lines: **33**
- Parsed logs: **33**
- Parse errors: **0**
- Normalized logs: **33**
- Preprocessed requests: **33**
- Scored records: **33**
- Alerts: **2**

## Label Distribution

- Benign: **31**
- Suspicious: **0**
- Malicious: **2**

## Top Attack Types

- `xss`: **1**
- `path_traversal`: **1**

## Top Matched Rule IDs

- `xss_script_tag`: **1**
- `xss_cookie_theft`: **1**
- `traversal_dotdot`: **1**
- `traversal_linux_passwd`: **1**

## Sample Alerts

- `203.0.113.42` `GET` `/search` => `malicious` (risk_score=87, attack_type=xss)
- `45.33.22.11` `GET` `/image/33719` => `malicious` (risk_score=92, attack_type=path_traversal)
