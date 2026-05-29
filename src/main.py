import argparse
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

try:
    from dotenv import load_dotenv
    HAS_DOTENV = True
except ImportError:
    HAS_DOTENV = False

from src.collector.file_collector import FileCollector
from src.detection.rule_detector import RuleDetector
from src.exporters.csv_exporter import CSVExporter
from src.exporters.jsonl_exporter import JSONLExporter
from src.exporters.markdown_exporter import MarkdownExporter
from src.exporters.mongodb_exporter import MongoDBExporter, HAS_PYMONGO
from src.features.feature_extractor import FeatureExtractor
from src.features.embedding_engine import EmbeddingEngine
from src.normalizer.normalizer import Normalizer
from src.parser.apache_parser import ApacheParser
from src.parser.iis_parser import IISParser
from src.parser.nginx_parser import NginxParser
from src.preprocessor.request_preprocessor import RequestPreprocessor
from src.reporting.postprocessor import PostProcessor
from src.reporting.report_generator import ReportGenerator
from src.scoring.risk_engine import RiskEngine

# Load environment variables if possible
if HAS_DOTENV:
    load_dotenv()

DEFAULT_RULES_PATH = os.getenv("DEFAULT_RULES_PATH", "data/labels/attack_patterns.yaml")

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


class LogPipeline:
    def __init__(
        self,
        server_type: str,
        rules_path: str = DEFAULT_RULES_PATH,
        use_mongo: bool = False,
        mongo_uri: Optional[str] = None,
        mongo_db: Optional[str] = None,
        mongo_coll: Optional[str] = None,
    ):
        self.server_type = server_type
        self.rules_path = rules_path
        self.use_mongo = use_mongo

        # Initialize components
        self.parser = self._get_parser(server_type)
        self.normalizer = Normalizer()
        self.preprocessor = RequestPreprocessor()
        self.detector = RuleDetector(rules_path=rules_path)
        self.feature_extractor = FeatureExtractor()
        self.embedding_engine = EmbeddingEngine()
        self.risk_engine = RiskEngine()

        # Exporters
        self.jsonl_exporter = JSONLExporter()
        self.csv_exporter = CSVExporter(preferred_fieldnames=RECORD_PREFERRED_COLUMNS)
        self.alert_csv_exporter = CSVExporter(preferred_fieldnames=ALERT_PREFERRED_COLUMNS)
        self.markdown_exporter = MarkdownExporter()

        self.mongo_exporter = None
        if use_mongo:
            uri = mongo_uri or os.getenv("MONGODB_URI")
            db = mongo_db or os.getenv("MONGODB_DB_NAME", "security_logs")
            coll = mongo_coll or os.getenv("MONGODB_COLLECTION_NAME", "unified_logs")
            if uri:
                self.mongo_exporter = MongoDBExporter(uri, db, coll)
            else:
                logging.warning("MongoDB enabled but MONGODB_URI not found in environment.")

    def _get_parser(self, server_type: str):
        value = server_type.lower()
        if value == "apache":
            return ApacheParser()
        if value == "nginx":
            return NginxParser()
        if value == "iis":
            return IISParser()
        raise ValueError(f"Unsupported server type: {server_type}")

    def run(self, input_path: str | Path, output_dir: str | Path) -> Dict:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        collector = FileCollector(str(input_path))
        read_records = collector.read_records()
        raw_lines = [item.get("line", "") for item in read_records]
        
        # 1. Raw lines
        raw_line_records = self._to_raw_line_records(read_records)
        self.jsonl_exporter.export(raw_line_records, output_path / "raw_lines.jsonl")

        # 2. Parsing
        parsed_logs = self.parser.parse_lines(raw_lines)
        self.jsonl_exporter.export(parsed_logs, output_path / "parsed_logs.jsonl")

        # 3. Normalization
        normalized_logs = [self.normalizer.normalize(row) for row in parsed_logs]
        self.jsonl_exporter.export(normalized_logs, output_path / "normalized_logs.jsonl")
        self.csv_exporter.export(normalized_logs, output_path / "normalized_logs.csv")

        # 4. Preprocessing
        preprocessed_requests = [self.preprocessor.preprocess(row) for row in normalized_logs]
        self.jsonl_exporter.export(preprocessed_requests, output_path / "preprocessed_requests.jsonl")

        # 5. Detection, Features, and Scoring
        scored_records: List[Dict] = []
        feature_rows: List[Dict] = []
        alerts: List[Dict] = []

        for request in preprocessed_requests:
            # Rule detection
            detected = self.detector.detect(request)
            # Feature extraction
            features = self.feature_extractor.extract(request)
            # Embedding (New: Vector Search requirement)
            embedding = self.embedding_engine.get_embedding(request.get("normalized_request", ""))

            record = dict(request)
            record.update(detected)
            for key, value in features.items():
                record[f"feature_{key}"] = value
            
            record["embedding"] = embedding  # Added for MongoDB Vector Search

            # Risk scoring
            record.update(self.risk_engine.score(record))
            
            scored_records.append(record)
            feature_rows.append(self._build_feature_row(record))

            if record.get("should_alert"):
                alerts.append(self._build_alert_record(record))

        # 6. Final exports
        self.csv_exporter.export(feature_rows, output_path / "features.csv")
        self.jsonl_exporter.export(alerts, output_path / "alerts.jsonl")
        self.alert_csv_exporter.export(alerts, output_path / "alerts.csv")

        # MongoDB Export if enabled
        if self.mongo_exporter:
            try:
                self.mongo_exporter.export(scored_records)
            except Exception as e:
                logging.error(f"Failed to export to MongoDB: {e}")

        # 7. Reporting
        postprocessor = PostProcessor()
        summary = postprocessor.build_summary(
            input_path=str(Path(input_path)),
            server_type=self.server_type,
            output_dir=str(output_path),
            rules_path=self.rules_path,
            raw_lines=raw_line_records,
            parsed_logs=parsed_logs,
            normalized_logs=normalized_logs,
            preprocessed_requests=preprocessed_requests,
            scored_records=scored_records,
            alerts=alerts,
        )
        summary["collector"] = {
            "decode_error_records": sum(1 for row in raw_line_records if row.get("decode_error")),
            "had_bom_records": sum(1 for row in raw_line_records if row.get("had_bom")),
            "continuation_merged_records": sum(1 for row in raw_line_records if row.get("was_continuation_merged")),
        }

        report_text = ReportGenerator().generate(summary, alerts)
        self.markdown_exporter.export(report_text, output_path / "report.md")

        run_summary_path = output_path / "run_summary.json"
        run_summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

        return summary

    def _to_raw_line_records(self, read_records: List[Dict]) -> List[Dict]:
        records: List[Dict] = []
        for idx, item in enumerate(read_records, start=1):
            line = item.get("line", "")
            digest = hashlib.sha1(str(line).encode("utf-8", errors="ignore")).hexdigest()[:12]
            records.append({
                "event_id": f"{self.server_type.lower()}:{idx}:{digest}",
                "line_number": idx,
                "server_type": self.server_type.lower(),
                "raw_line": line,
                "parse_status": "raw",
                "parse_error": False,
                "error_message": None,
                "encoding_used": item.get("encoding_used"),
                "decode_error": bool(item.get("decode_error", False)),
                "had_bom": bool(item.get("had_bom", False)),
                "was_continuation_merged": bool(item.get("was_continuation_merged", False)),
                "physical_line_start": item.get("physical_line_start"),
                "physical_line_end": item.get("physical_line_end"),
            })
        return records

    def _build_feature_row(self, record: Dict) -> Dict:
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

    def _build_alert_record(self, record: Dict) -> Dict:
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
    use_mongo: bool = False,
) -> Dict:
    pipeline = LogPipeline(server_type, rules_path, use_mongo=use_mongo)
    return pipeline.run(input_path, output_dir)


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Web Server Log Parser + Rule-based Web Attack Detection (MongoDB & AI Ready)"
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
    parser.add_argument("--mongo", action="store_true", help="Export results to MongoDB Atlas")
    return parser


def main() -> None:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    cli = build_cli()
    args = cli.parse_args()

    summary = run_pipeline(
        input_path=args.input,
        server_type=args.server_type,
        output_dir=args.output_dir,
        rules_path=args.rules,
        use_mongo=args.mongo,
    )

    counts = summary.get("counts", {})
    print("\n[+] Pipeline finished")
    print(f"[+] Raw lines: {counts.get('raw_lines', 0)}")
    print(f"[+] Parsed logs: {counts.get('parsed_logs', 0)}")
    print(f"[+] Parse errors: {counts.get('parse_errors', 0)}")
    print(f"[+] Alerts: {counts.get('alerts', 0)}")
    if args.mongo:
        print("[+] Exported to MongoDB Atlas")
    collector_info = summary.get("collector", {})
    print(f"[+] Decode fallback records: {collector_info.get('decode_error_records', 0)}")
    print(f"[+] Output dir: {summary.get('output_dir')}")


if __name__ == "__main__":
    main()
