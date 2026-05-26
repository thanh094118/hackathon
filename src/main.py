import argparse
import hashlib
import json
from pathlib import Path
from typing import Dict, List

from src.collector.file_collector import FileCollector
from src.detection.rule_detector import RuleDetector
from src.exporters.csv_exporter import CSVExporter
from src.exporters.jsonl_exporter import JSONLExporter
from src.exporters.markdown_exporter import MarkdownExporter
from src.features.feature_extractor import FeatureExtractor
from src.normalizer.normalizer import Normalizer
from src.parser.apache_parser import ApacheParser
from src.parser.iis_parser import IISParser
from src.parser.nginx_parser import NginxParser
from src.preprocessor.request_preprocessor import RequestPreprocessor
from src.reporting.postprocessor import PostProcessor
from src.reporting.report_generator import ReportGenerator
from src.scoring.risk_engine import RiskEngine


DEFAULT_RULES_PATH = "data/labels/attack_patterns.yaml"

RECORD_PREFERRED_COLUMNS = [
    "event_id",
    "line_number",
    "parse_status",
    "parse_error",
    "error_message",
    "timestamp",
    "source_ip",
    "http_method",
    "original_url",
    "uri",
    "query_string",
    "status_code",
    "response_size",
    "user_agent",
    "referrer",
    "server_type",
    "risk_score",
    "risk_level",
    "final_label",
    "attack_type",
    "matched_rule_ids",
]

ALERT_PREFERRED_COLUMNS = [
    "event_id",
    "line_number",
    "timestamp",
    "source_ip",
    "http_method",
    "original_url",
    "uri",
    "query_string",
    "status_code",
    "response_size",
    "server_type",
    "rule_label",
    "rule_score",
    "rule_severity",
    "risk_score",
    "risk_level",
    "final_label",
    "attack_type",
    "matched_rule_ids",
    "matched_rules",
    "normalized_request",
    "raw_log",
]


def get_parser(server_type: str):
    value = server_type.lower()
    if value == "apache":
        return ApacheParser()
    if value == "nginx":
        return NginxParser()
    if value == "iis":
        return IISParser()
    raise ValueError(f"Unsupported server type: {server_type}")


def to_raw_line_records(lines: List[str], server_type: str) -> List[Dict]:
    records = []
    for idx, line in enumerate(lines, start=1):
        digest = hashlib.sha1(str(line).encode("utf-8", errors="ignore")).hexdigest()[:12]
        records.append({
            "event_id": f"{server_type.lower()}:{idx}:{digest}",
            "line_number": idx,
            "server_type": server_type.lower(),
            "raw_line": line,
            "parse_status": "raw",
            "parse_error": False,
            "error_message": None,
        })
    return records


def build_feature_row(record: Dict) -> Dict:
    row = {
        "line_number": record.get("line_number"),
        "event_id": record.get("event_id"),
        "parse_status": record.get("parse_status"),
        "parse_error": record.get("parse_error"),
        "error_message": record.get("error_message"),
        "source_ip": record.get("source_ip"),
        "http_method": record.get("http_method"),
        "original_url": record.get("original_url"),
        "uri": record.get("uri"),
        "query_string": record.get("query_string"),
        "normalized_request": record.get("normalized_request"),
        "server_type": record.get("server_type"),
    }
    for key, value in record.items():
        if key.startswith("feature_"):
            row[key] = value
    return row


def build_alert_record(record: Dict) -> Dict:
    return {
        "line_number": record.get("line_number"),
        "event_id": record.get("event_id"),
        "timestamp": record.get("timestamp"),
        "source_ip": record.get("source_ip"),
        "http_method": record.get("http_method"),
        "original_url": record.get("original_url"),
        "uri": record.get("uri"),
        "query_string": record.get("query_string"),
        "status_code": record.get("status_code"),
        "response_size": record.get("response_size"),
        "user_agent": record.get("user_agent"),
        "referrer": record.get("referrer"),
        "server_type": record.get("server_type"),
        "rule_label": record.get("rule_label"),
        "rule_score": record.get("rule_score"),
        "rule_severity": record.get("rule_severity"),
        "risk_score": record.get("risk_score"),
        "risk_level": record.get("risk_level"),
        "final_label": record.get("final_label"),
        "attack_type": record.get("attack_type"),
        "attack_types": record.get("attack_types", []),
        "matched_rule_ids": record.get("matched_rule_ids", []),
        "matched_rules": record.get("matched_rules", []),
        "normalized_request": record.get("normalized_request"),
        "parse_status": record.get("parse_status"),
        "parse_error": record.get("parse_error"),
        "error_message": record.get("error_message"),
        "raw_log": record.get("raw_log"),
    }


def run_pipeline(
    *,
    input_path: str | Path,
    server_type: str,
    output_dir: str | Path,
    rules_path: str = DEFAULT_RULES_PATH,
) -> Dict:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    collector = FileCollector(str(input_path))
    parser = get_parser(server_type)
    normalizer = Normalizer()
    preprocessor = RequestPreprocessor()
    detector = RuleDetector(rules_path=rules_path)
    feature_extractor = FeatureExtractor()
    risk_engine = RiskEngine()

    jsonl_exporter = JSONLExporter()
    csv_exporter = CSVExporter(preferred_fieldnames=RECORD_PREFERRED_COLUMNS)
    alert_csv_exporter = CSVExporter(preferred_fieldnames=ALERT_PREFERRED_COLUMNS)
    markdown_exporter = MarkdownExporter()

    raw_lines = collector.read_all()
    raw_line_records = to_raw_line_records(raw_lines, server_type)
    jsonl_exporter.export(raw_line_records, output_path / "raw_lines.jsonl")

    parsed_logs = parser.parse_lines(raw_lines)
    jsonl_exporter.export(parsed_logs, output_path / "parsed_logs.jsonl")

    normalized_logs = [normalizer.normalize(row) for row in parsed_logs]
    jsonl_exporter.export(normalized_logs, output_path / "normalized_logs.jsonl")
    csv_exporter.export(normalized_logs, output_path / "normalized_logs.csv")

    preprocessed_requests = [preprocessor.preprocess(row) for row in normalized_logs]
    jsonl_exporter.export(preprocessed_requests, output_path / "preprocessed_requests.jsonl")

    scored_records: List[Dict] = []
    feature_rows: List[Dict] = []
    alerts: List[Dict] = []

    for request in preprocessed_requests:
        detected = detector.detect(request)
        features = feature_extractor.extract(request)

        record = dict(request)
        record.update(detected)
        for key, value in features.items():
            record[f"feature_{key}"] = value

        record.update(risk_engine.score(record))
        scored_records.append(record)
        feature_rows.append(build_feature_row(record))

        if record.get("should_alert"):
            alerts.append(build_alert_record(record))

    csv_exporter.export(feature_rows, output_path / "features.csv")
    jsonl_exporter.export(alerts, output_path / "alerts.jsonl")
    alert_csv_exporter.export(alerts, output_path / "alerts.csv")

    postprocessor = PostProcessor()
    summary = postprocessor.build_summary(
        input_path=str(Path(input_path)),
        server_type=server_type,
        output_dir=str(output_path),
        rules_path=rules_path,
        raw_lines=raw_line_records,
        parsed_logs=parsed_logs,
        normalized_logs=normalized_logs,
        preprocessed_requests=preprocessed_requests,
        scored_records=scored_records,
        alerts=alerts,
    )

    report_text = ReportGenerator().generate(summary, alerts)
    markdown_exporter.export(report_text, output_path / "report.md")

    run_summary_path = output_path / "run_summary.json"
    run_summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    return summary


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Web Server Log Parser + Rule-based Web Attack Detection (non-ML pipeline)"
    )
    parser.add_argument("--input", required=True, help="Path to one access log file")
    parser.add_argument(
        "--server-type",
        required=True,
        choices=("apache", "nginx", "iis"),
        help="Input log server type",
    )
    parser.add_argument("--output-dir", required=True, help="Directory for all generated outputs")
    parser.add_argument("--rules", default=DEFAULT_RULES_PATH, help="YAML rule file path")
    return parser


def main() -> None:
    cli = build_cli()
    args = cli.parse_args()

    summary = run_pipeline(
        input_path=args.input,
        server_type=args.server_type,
        output_dir=args.output_dir,
        rules_path=args.rules,
    )

    counts = summary.get("counts", {})
    print("[+] Pipeline finished")
    print(f"[+] Raw lines: {counts.get('raw_lines', 0)}")
    print(f"[+] Parsed logs: {counts.get('parsed_logs', 0)}")
    print(f"[+] Parse errors: {counts.get('parse_errors', 0)}")
    print(f"[+] Alerts: {counts.get('alerts', 0)}")
    print(f"[+] Output dir: {summary.get('output_dir')}")


if __name__ == "__main__":
    main()
