import argparse
import csv
import json
from pathlib import Path
from typing import Dict, List, Optional

from src.collector.file_collector import FileCollector
from src.detection.rule_detector import RuleDetector
from src.features.feature_extractor import FeatureExtractor
from src.normalizer.normalizer import Normalizer
from src.parser.apache_parser import ApacheParser
from src.parser.iis_parser import IISParser
from src.parser.nginx_parser import NginxParser
from src.preprocessor.request_preprocessor import RequestPreprocessor


DEFAULT_INPUT_DIR = "input"
DEFAULT_OUTPUT_DIR = "outputs"


def get_parser(server_type: str):
    normalized = server_type.lower()
    if normalized == "apache":
        return ApacheParser()
    if normalized == "nginx":
        return NginxParser()
    if normalized == "iis":
        return IISParser()
    raise ValueError(f"Unsupported server type: {server_type}")


def write_jsonl(records: List[Dict], output_path: Path) -> None:
    with output_path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_csv(records: List[Dict], output_path: Path) -> None:
    if not records:
        output_path.write_text("", encoding="utf-8")
        return

    preferred = [
        "timestamp", "source_ip", "http_method", "uri", "query_string",
        "status_code", "response_size", "user_agent", "referrer",
        "server_type", "line_number", "parse_error", "error_message", "raw_log",
    ]

    all_keys = set()
    for record in records:
        all_keys.update(record.keys())

    fieldnames = preferred + sorted(k for k in all_keys if k not in preferred)

    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)


def flatten_for_csv(record: Dict) -> Dict:
    flattened = dict(record)
    for key in ["matched_rules", "matched_rule_ids", "attack_types"]:
        if isinstance(flattened.get(key), (list, dict)):
            flattened[key] = json.dumps(flattened[key], ensure_ascii=False)
    return flattened


def build_alert(record: Dict, rule_result: Dict) -> Dict:
    return {
        "event_type": "web_attack_detection",
        "timestamp": record.get("timestamp"),
        "source_ip": record.get("source_ip"),
        "http_method": record.get("http_method"),
        "uri": record.get("uri"),
        "query_string": record.get("query_string"),
        "status_code": record.get("status_code"),
        "response_size": record.get("response_size"),
        "user_agent": record.get("user_agent"),
        "server_type": record.get("server_type"),
        "label": rule_result.get("rule_label"),
        "attack_type": rule_result.get("attack_type"),
        "attack_types": rule_result.get("attack_types", []),
        "risk_score": rule_result.get("rule_score"),
        "severity": rule_result.get("rule_severity"),
        "matched_rule_ids": rule_result.get("matched_rule_ids", []),
        "matched_rules": rule_result.get("matched_rules", []),
        "detection_source": "rule",
        "normalized_request": record.get("normalized_request"),
        "raw_log": record.get("raw_log"),
    }


def process_one_log(
    input_log_path: Path,
    server_type: str,
    output_path: Path,
    detector: RuleDetector,
    normalizer: Normalizer,
    preprocessor: RequestPreprocessor,
    feature_extractor: FeatureExtractor,
) -> Optional[Dict]:
    try:
        parser = get_parser(server_type)
    except ValueError:
        print(f"[!] Skip unsupported server type '{server_type}' for: {input_log_path}")
        return None

    reader = FileCollector(str(input_log_path))
    parsed_records = parser.parse_lines(reader.read_lines())

    normalized_records = [normalizer.normalize(record) for record in parsed_records]
    preprocessed_records = [preprocessor.preprocess(record) for record in normalized_records]

    detected_records = []
    alerts = []
    for record in preprocessed_records:
        rule_result = detector.detect(record)
        enriched = dict(record)
        enriched.update(rule_result)
        detected_records.append(enriched)
        if rule_result.get("rule_label") in {"suspicious", "malicious"}:
            alerts.append(build_alert(record, rule_result))

    processed_records = [feature_extractor.enrich(record) for record in detected_records]

    write_jsonl(normalized_records, output_path / "normalized_logs.jsonl")
    write_csv(normalized_records, output_path / "normalized_logs.csv")
    write_jsonl(processed_records, output_path / "processed_logs.jsonl")
    write_csv([flatten_for_csv(r) for r in processed_records], output_path / "processed_logs.csv")
    write_jsonl(alerts, output_path / "alerts.jsonl")
    write_csv([flatten_for_csv(a) for a in alerts], output_path / "alerts.csv")

    parse_errors = sum(1 for r in normalized_records if r.get("parse_error"))
    suspicious = sum(1 for r in detected_records if r.get("rule_label") == "suspicious")
    malicious = sum(1 for r in detected_records if r.get("rule_label") == "malicious")

    print(f"[+] Processed        : {input_log_path}")
    print(f"[+] Server type      : {server_type}")
    print(f"[+] Parsed records   : {len(parsed_records)}")
    print(f"[+] Parse errors     : {parse_errors}")
    print(f"[+] Suspicious       : {suspicious}")
    print(f"[+] Malicious        : {malicious}")
    print(f"[+] Alerts           : {len(alerts)}")
    print(f"[+] Output dir       : {output_path}")

    return {
        "parsed_records": len(parsed_records),
        "parse_errors": parse_errors,
        "suspicious": suspicious,
        "malicious": malicious,
        "alerts": len(alerts),
    }


def run_pipeline(rules_path: str) -> None:
    collector = FileCollector(DEFAULT_INPUT_DIR)
    jobs = collector.collect_jobs(DEFAULT_OUTPUT_DIR)

    if not jobs:
        print(f"[!] No access logs found in {DEFAULT_INPUT_DIR}/ (pattern: access*.log)")
        return

    detector = RuleDetector(rules_path=rules_path)
    normalizer = Normalizer()
    preprocessor = RequestPreprocessor()
    feature_extractor = FeatureExtractor()

    totals = {
        "files": 0,
        "parsed_records": 0,
        "parse_errors": 0,
        "suspicious": 0,
        "malicious": 0,
        "alerts": 0,
    }

    print("[+] Web Log AI Detector - Batch Pipeline")
    print(f"[+] Input root       : {DEFAULT_INPUT_DIR}/")
    print(f"[+] Output root      : {DEFAULT_OUTPUT_DIR}/")
    print(f"[+] Rules file       : {rules_path}")
    print(f"[+] Discovered files : {len(jobs)}")

    for job in jobs:
        metrics = process_one_log(
            input_log_path=job.input_log_path,
            server_type=job.server_type,
            output_path=job.output_dir,
            detector=detector,
            normalizer=normalizer,
            preprocessor=preprocessor,
            feature_extractor=feature_extractor,
        )

        if metrics is None:
            continue

        totals["files"] += 1
        totals["parsed_records"] += metrics["parsed_records"]
        totals["parse_errors"] += metrics["parse_errors"]
        totals["suspicious"] += metrics["suspicious"]
        totals["malicious"] += metrics["malicious"]
        totals["alerts"] += metrics["alerts"]

    print("[+] Summary")
    print(f"[+] Files processed  : {totals['files']}")
    print(f"[+] Parsed records   : {totals['parsed_records']}")
    print(f"[+] Parse errors     : {totals['parse_errors']}")
    print(f"[+] Suspicious total : {totals['suspicious']}")
    print(f"[+] Malicious total  : {totals['malicious']}")
    print(f"[+] Alerts total     : {totals['alerts']}")
    print("[+] B3 completed: Module 4 + Module 5 + Module 6 are working.")
    print("[!] Module 7 AI/NLP is intentionally not implemented yet.")


def main():
    cli = argparse.ArgumentParser(description="Web Log AI Detector - Batch Pipeline")
    cli.add_argument("--rules", default="data/labels/attack_patterns.yaml", help="Path to YAML rule file")
    args = cli.parse_args()

    run_pipeline(rules_path=args.rules)


if __name__ == "__main__":
    main()
