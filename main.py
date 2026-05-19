import argparse
import csv
import json
from pathlib import Path
from typing import Dict, List

from src.collector.file_collector import FileCollector
from src.detection.rule_detector import RuleDetector
from src.features.feature_extractor import FeatureExtractor
from src.normalizer.normalizer import Normalizer
from src.parser.apache_parser import ApacheParser
from src.parser.iis_parser import IISParser
from src.parser.nginx_parser import NginxParser
from src.preprocessor.request_preprocessor import RequestPreprocessor


def get_parser(server_type: str):
    if server_type == "apache":
        return ApacheParser()
    if server_type == "nginx":
        return NginxParser()
    if server_type == "iis":
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


def run_pipeline(input_path: str, server_type: str, output_dir: str, rules_path: str) -> None:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Module 1: Collector
    collector = FileCollector(input_path)
    lines = collector.read_all()

    # Module 2: Parser
    parser = get_parser(server_type)
    parsed_records = parser.parse_lines(lines)

    # Module 3: Normalizer
    normalizer = Normalizer()
    normalized_records = [normalizer.normalize(record) for record in parsed_records]

    # Module 4: Request Preprocessor
    preprocessor = RequestPreprocessor()
    preprocessed_records = [preprocessor.preprocess(record) for record in normalized_records]

    # Module 5: Rule-based Detector
    detector = RuleDetector(rules_path=rules_path)
    detected_records = []
    alerts = []

    for record in preprocessed_records:
        rule_result = detector.detect(record)
        enriched = dict(record)
        enriched.update(rule_result)
        detected_records.append(enriched)

        if rule_result.get("rule_label") in {"suspicious", "malicious"}:
            alerts.append(build_alert(record, rule_result))

    # Module 6: Feature Extractor
    feature_extractor = FeatureExtractor()
    processed_records = [feature_extractor.enrich(record) for record in detected_records]

    write_jsonl(normalized_records, output_path / "normalized_logs.jsonl")
    write_csv(normalized_records, output_path / "normalized_logs.csv")

    write_jsonl(processed_records, output_path / "processed_logs.jsonl")
    write_csv([flatten_for_csv(r) for r in processed_records], output_path / "processed_logs.csv")

    write_jsonl(alerts, output_path / "alerts.jsonl")
    write_csv([flatten_for_csv(a) for a in alerts], output_path / "alerts.csv")

    print("[+] Web Log AI Detector - MVP CLI Pipeline")
    print(f"[+] Input file       : {input_path}")
    print(f"[+] Server type      : {server_type}")
    print(f"[+] Rules file       : {rules_path}")
    print(f"[+] Raw lines        : {len(lines)}")
    print(f"[+] Parsed records   : {len(parsed_records)}")
    print(f"[+] Parse errors     : {sum(1 for r in normalized_records if r.get('parse_error'))}")
    print(f"[+] Suspicious       : {sum(1 for r in detected_records if r.get('rule_label') == 'suspicious')}")
    print(f"[+] Malicious        : {sum(1 for r in detected_records if r.get('rule_label') == 'malicious')}")
    print(f"[+] Alerts           : {len(alerts)}")
    print(f"[+] Output dir       : {output_path}")
    print("[+] B3 completed: Module 4 + Module 5 + Module 6 are working.")
    print("[!] Module 7 AI/NLP is intentionally not implemented yet.")


def main():
    cli = argparse.ArgumentParser(description="Web Log AI Detector - MVP CLI Pipeline")
    cli.add_argument("--input", required=True, help="Path to access log file")
    cli.add_argument("--server", required=True, choices=["apache", "nginx", "iis"], help="Web server log type")
    cli.add_argument("--output", default="outputs/", help="Output directory")
    cli.add_argument("--rules", default="data/labels/attack_patterns.yaml", help="Path to YAML rule file")
    args = cli.parse_args()

    run_pipeline(
        input_path=args.input,
        server_type=args.server,
        output_dir=args.output,
        rules_path=args.rules,
    )


if __name__ == "__main__":
    main()
