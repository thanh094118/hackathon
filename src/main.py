import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional

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
from src.parser.server_type_detector import detect_server_type
from src.preprocessor.request_preprocessor import RequestPreprocessor
from src.reporting.postprocessor import PostProcessor
from src.reporting.report_generator import ReportGenerator
from src.scoring.risk_engine import RiskEngine


DEFAULT_RULES_PATH = "src/rules/attack_patterns.yaml"

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


def _build_event_id(*, server_type: str, line_number: int, raw_line: str, source_id: Optional[str] = None) -> str:
    digest = hashlib.sha1(str(raw_line).encode("utf-8", errors="ignore")).hexdigest()[:12]
    if source_id:
        return f"{server_type.lower()}:{line_number}:{source_id}:{digest}"
    return f"{server_type.lower()}:{line_number}:{digest}"


def to_raw_line_records(lines: List[str], server_type: str, source_id: Optional[str] = None) -> List[Dict]:
    records = []
    for idx, line in enumerate(lines, start=1):
        records.append({
            "event_id": _build_event_id(
                server_type=server_type,
                line_number=idx,
                raw_line=line,
                source_id=source_id,
            ),
            "line_number": idx,
            "server_type": server_type.lower(),
            "raw_line": line,
            "parse_status": "raw",
            "flags": [],
            "physical_line_range": [idx, idx],
        })
    return records


def to_raw_line_records_with_metadata(
    read_records: List[Dict],
    server_type: str,
    source_id: Optional[str] = None,
) -> List[Dict]:
    records: List[Dict] = []
    for idx, item in enumerate(read_records, start=1):
        line = item.get("line", "")
        records.append({
            "event_id": _build_event_id(
                server_type=server_type,
                line_number=idx,
                raw_line=line,
                source_id=source_id,
            ),
            "line_number": idx,
            "server_type": server_type.lower(),
            "raw_line": line,
            "parse_status": "raw",
            "flags": list(item.get("flags", [])),
            "physical_line_range": list(item.get("physical_line_range", [idx, idx])),
        })
    return records


def build_feature_row(record: Dict) -> Dict:
    excluded_feature_columns = {
        "feature_status_code",
        "feature_response_size",
        "feature_feature_schema_version",
    }
    row = {}
    for key, value in record.items():
        if key.startswith("feature_") and key not in excluded_feature_columns:
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
    server_type: Optional[str],
    output_dir: str | Path,
    rules_path: str = DEFAULT_RULES_PATH,
) -> Dict:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    input_stem = Path(input_path).stem

    stage_to_module_dir = {
        "collect": "collector_results",
        "parser": "parser_results",
        "normalize": "normalizer_results",
        "preprocess": "preprocessor_results",
        "detect": "detector_results",
        "extract": "feature_results",
    }

    def stage_file(stage_name: str, suffix: str) -> Path:
        base = output_path / stage_to_module_dir[stage_name]
        base.mkdir(parents=True, exist_ok=True)
        return base / f"{prefix}_{suffix}"

    collector = FileCollector(str(input_path))
    normalizer = Normalizer()
    preprocessor = RequestPreprocessor()
    detector = RuleDetector(rules_path=rules_path)
    feature_extractor = FeatureExtractor()
    risk_engine = RiskEngine()

    jsonl_exporter = JSONLExporter()
    csv_exporter = CSVExporter(preferred_fieldnames=RECORD_PREFERRED_COLUMNS)
    alert_csv_exporter = CSVExporter(preferred_fieldnames=ALERT_PREFERRED_COLUMNS)
    feature_csv_exporter = CSVExporter()
    markdown_exporter = MarkdownExporter()

    read_records = collector.read_records()
    raw_lines = [item.get("line", "") for item in read_records]
    resolved_server_type = (server_type or detect_server_type(raw_lines)).lower()
    parser = get_parser(resolved_server_type)
    parser.set_resolved_server_type(resolved_server_type)
    source_id = hashlib.sha1(str(Path(input_path).resolve()).encode("utf-8", errors="ignore")).hexdigest()[:8]
    parser.set_event_namespace(source_id)
    prefix = f"{resolved_server_type}_{input_stem}"
    raw_line_records = to_raw_line_records_with_metadata(read_records, resolved_server_type, source_id=source_id)
    jsonl_exporter.export(raw_line_records, stage_file("collect", "raw_lines.jsonl"))
    flag_counts = Counter(
        flag
        for row in raw_line_records
        for flag in row.get("flags", [])
    )
    for flag in sorted(flag_counts):
        count = int(flag_counts.get(flag, 0))
        if count > 0:
            print(
                f"[collector][flag] {Path(input_path).name}: {flag}={count}",
                flush=True,
            )

    parsed_logs = list(parser.parse_lines(raw_lines))
    jsonl_exporter.export(parsed_logs, stage_file("parser", "parsed_logs.jsonl"))

    normalized_logs = [normalizer.normalize(row) for row in parsed_logs]
    jsonl_exporter.export(normalized_logs, stage_file("normalize", "normalized_logs.jsonl"))
    csv_exporter.export(normalized_logs, stage_file("normalize", "normalized_logs.csv"))

    preprocessed_requests = [preprocessor.preprocess(row) for row in normalized_logs]
    jsonl_exporter.export(preprocessed_requests, stage_file("preprocess", "preprocessed_requests.jsonl"))

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

    feature_csv_exporter.export(feature_rows, stage_file("extract", "features.csv"))
    jsonl_exporter.export(alerts, stage_file("detect", "alerts.jsonl"))
    alert_csv_exporter.export(alerts, stage_file("detect", "alerts.csv"))

    postprocessor = PostProcessor()
    summary = postprocessor.build_summary(
        input_path=str(Path(input_path)),
        server_type=resolved_server_type,
        output_dir=str(output_path),
        rules_path=rules_path,
        raw_lines=raw_line_records,
        parsed_logs=parsed_logs,
        normalized_logs=normalized_logs,
        preprocessed_requests=preprocessed_requests,
        scored_records=scored_records,
        alerts=alerts,
    )
    summary["collector"] = {
        "decode_error_records": sum(
            1 for row in raw_line_records
            if "decode_fallback_latin1" in set(row.get("flags", []))
        ),
        "had_bom_records": sum(
            1 for row in raw_line_records
            if "had_utf8_bom" in set(row.get("flags", []))
        ),
        "continuation_merged_records": sum(
            1 for row in raw_line_records
            if "continuation_merged" in set(row.get("flags", []))
        ),
    }

    report_dir = output_path / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_text = ReportGenerator().generate(summary, alerts)
    markdown_exporter.export(report_text, report_dir / f"{prefix}_report.md")

    run_summary_path = report_dir / f"{prefix}_run_summary.json"
    run_summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    return summary


def run_pipeline_batch(
    *,
    input_path: str | Path,
    server_type: Optional[str],
    output_dir: str | Path,
    rules_path: str = DEFAULT_RULES_PATH,
) -> Dict:
    path = Path(input_path)
    if path.is_file():
        return run_pipeline(
            input_path=path,
            server_type=server_type,
            output_dir=output_dir,
            rules_path=rules_path,
        )

    if not path.is_dir():
        raise ValueError(f"Input path is not a file or directory: {path}")

    supported_suffixes = {".log", ".txt", ".csv", ".json", ".jsonl"}
    candidates = [
        item for item in sorted(path.rglob("*"))
        if item.is_file() and item.suffix.lower() in supported_suffixes
    ]

    runs: List[Dict] = []
    skipped: List[Dict] = []
    total_counts: Dict[str, int] = {}
    output_dir_path = Path(output_dir)
    output_dir_path.mkdir(parents=True, exist_ok=True)

    total_files = len(candidates)
    print(f"[+] Batch mode: found {total_files} files", flush=True)

    for index, item in enumerate(candidates, start=1):
        print(f"[{index}/{total_files}] Processing: {item}", flush=True)
        try:
            summary = run_pipeline(
                input_path=item,
                server_type=server_type,
                output_dir=output_dir_path,
                rules_path=rules_path,
            )
            runs.append(summary)
            for key, value in summary.get("counts", {}).items():
                total_counts[key] = total_counts.get(key, 0) + int(value)
            print(f"[{index}/{total_files}] Done: {item.name}", flush=True)
        except Exception as exc:
            skipped.append({"input_path": str(item), "error": str(exc)})
            print(f"[{index}/{total_files}] Skipped: {item.name} ({exc})", flush=True)

    return {
        "mode": "batch",
        "input_path": str(path),
        "output_dir": str(output_dir_path),
        "counts": total_counts,
        "processed_files": len(runs),
        "skipped_files": len(skipped),
        "runs": runs,
        "skipped": skipped,
    }


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Web Server Log Parser + Rule-based Web Attack Detection (non-ML pipeline)"
    )
    parser.add_argument("--input", required=True, help="Path to one input file or a folder of files")
    parser.add_argument(
        "--server-type",
        required=False,
        choices=("apache", "nginx", "iis"),
        help="Input log server type (optional, auto-detected when omitted)",
    )
    parser.add_argument("--output-dir", default="outputs", help="Directory for all generated outputs")
    parser.add_argument("--rules", default=DEFAULT_RULES_PATH, help="YAML rule file path")
    return parser


def main() -> None:
    cli = build_cli()
    args = cli.parse_args()

    summary = run_pipeline_batch(
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
    collector_info = summary.get("collector", {})
    print(f"[+] Decode fallback records: {collector_info.get('decode_error_records', 0)}")
    if summary.get("mode") == "batch":
        print(f"[+] Processed files: {summary.get('processed_files', 0)}")
        print(f"[+] Skipped files: {summary.get('skipped_files', 0)}")
        # Show only concise skip list (no stage result logs).
        skipped = summary.get("skipped", [])
        if skipped:
            print("[+] Skipped details:")
            for item in skipped:
                print(f"    - {item.get('input_path')}: {item.get('error')}")
    print(f"[+] Output dir: {summary.get('output_dir')}")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
