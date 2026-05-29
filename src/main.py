import argparse
import hashlib
import json
import logging
import os
import sys
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

DEFAULT_RULES_PATH = os.getenv("DEFAULT_RULES_PATH", "src/rules/attack_patterns.yaml")
STAGE_CHOICES = ("all", "collect", "parser", "normalize", "preprocess", "detect", "extract")

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
        server_type: Optional[str],
        rules_path: str = DEFAULT_RULES_PATH,
        stage: str = "all",
        use_mongo: bool = False,
        mongo_uri: Optional[str] = None,
        mongo_db: Optional[str] = None,
        mongo_coll: Optional[str] = None,
    ):
        self.server_type = server_type
        self.rules_path = rules_path
        self.stage = stage
        self.use_mongo = use_mongo

        # Initialize components
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
        self.feature_csv_exporter = CSVExporter()
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

    def detect_server_type(self, lines: List[str]) -> str:
        non_empty = [line for line in lines if str(line).strip()]
        if any(str(line).lstrip().startswith("#Fields:") for line in non_empty):
            return "iis"
        if any(str(line).lstrip().startswith("#Software:") for line in non_empty):
            return "iis"

        sample = non_empty[:200]
        apache_ok = sum(1 for row in ApacheParser().parse_lines(sample) if row.get("parse_status") == "success")
        nginx_ok = sum(1 for row in NginxParser().parse_lines(sample) if row.get("parse_status") == "success")
        if nginx_ok > apache_ok:
            return "nginx"
        return "apache"

    def run(self, input_path: str | Path, output_dir: str | Path) -> Dict:
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

        collector = FileCollector(str(input_path))
        read_records = collector.read_records()
        raw_lines = [item.get("line", "") for item in read_records]
        
        resolved_server_type = (self.server_type or self.detect_server_type(raw_lines)).lower()
        parser = self._get_parser(resolved_server_type)
        parser.set_resolved_server_type(resolved_server_type)
        
        source_id = hashlib.sha1(str(Path(input_path).resolve()).encode("utf-8", errors="ignore")).hexdigest()[:8]
        parser.set_event_namespace(source_id)
        
        prefix = f"{resolved_server_type}_{input_stem}"

        def stage_file(stage_name: str, suffix: str) -> Path:
            base = output_path / stage_to_module_dir[stage_name]
            base.mkdir(parents=True, exist_ok=True)
            return base / f"{prefix}_{suffix}"

        # 1. Raw lines
        raw_line_records = self._to_raw_line_records_with_metadata(read_records, resolved_server_type, source_id=source_id)
        self.jsonl_exporter.export(raw_line_records, stage_file("collect", "raw_lines.jsonl"))
        
        if self.stage == "collect":
            return {"stage": self.stage, "output_dir": str(output_path), "counts": {"raw_lines": len(raw_line_records)}}

        # 2. Parsing
        parsed_logs = list(parser.parse_lines(raw_lines))
        self.jsonl_exporter.export(parsed_logs, stage_file("parser", "parsed_logs.jsonl"))
        
        if self.stage == "parser":
            return {"stage": self.stage, "output_dir": str(output_path), "counts": {"raw_lines": len(raw_line_records), "parsed_logs": len(parsed_logs)}}

        # 3. Normalization
        normalized_logs = [self.normalizer.normalize(row) for row in parsed_logs]
        self.jsonl_exporter.export(normalized_logs, stage_file("normalize", "normalized_logs.jsonl"))
        self.csv_exporter.export(normalized_logs, stage_file("normalize", "normalized_logs.csv"))
        
        if self.stage == "normalize":
            return {"stage": self.stage, "output_dir": str(output_path), "counts": {"raw_lines": len(raw_line_records), "parsed_logs": len(parsed_logs), "normalized_logs": len(normalized_logs)}}

        # 4. Preprocessing
        preprocessed_requests = [self.preprocessor.preprocess(row) for row in normalized_logs]
        self.jsonl_exporter.export(preprocessed_requests, stage_file("preprocess", "preprocessed_requests.jsonl"))
        
        if self.stage == "preprocess":
            return {"stage": self.stage, "output_dir": str(output_path), "counts": {"raw_lines": len(raw_line_records), "parsed_logs": len(parsed_logs), "normalized_logs": len(normalized_logs), "preprocessed_requests": len(preprocessed_requests)}}

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
        if self.stage in ("all", "extract"):
            self.feature_csv_exporter.export(feature_rows, stage_file("extract", "features.csv"))
        if self.stage in ("all", "detect"):
            self.jsonl_exporter.export(alerts, stage_file("detect", "alerts.jsonl"))
            self.alert_csv_exporter.export(alerts, stage_file("detect", "alerts.csv"))

        if self.stage in ("detect", "extract"):
            return {
                "stage": self.stage,
                "output_dir": str(output_path),
                "counts": {
                    "raw_lines": len(raw_line_records),
                    "parsed_logs": len(parsed_logs),
                    "normalized_logs": len(normalized_logs),
                    "preprocessed_requests": len(preprocessed_requests),
                    "alerts": len(alerts),
                    "features": len(feature_rows),
                },
            }

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
            server_type=resolved_server_type,
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

        report_dir = output_path / "report"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_text = ReportGenerator().generate(summary, alerts)
        self.markdown_exporter.export(report_text, report_dir / f"{prefix}_report.md")

        run_summary_path = report_dir / f"{prefix}_run_summary.json"
        run_summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

        return summary

    def _to_raw_line_records_with_metadata(
        self,
        read_records: List[Dict],
        server_type: str,
        source_id: Optional[str] = None,
    ) -> List[Dict]:
        records: List[Dict] = []
        for idx, item in enumerate(read_records, start=1):
            line = item.get("line", "")
            digest = hashlib.sha1(str(line).encode("utf-8", errors="ignore")).hexdigest()[:12]
            event_id = f"{server_type.lower()}:{idx}:{source_id}:{digest}" if source_id else f"{server_type.lower()}:{idx}:{digest}"
            records.append({
                "event_id": event_id,
                "line_number": idx,
                "server_type": server_type.lower(),
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
    server_type: Optional[str],
    output_dir: str | Path,
    rules_path: str = DEFAULT_RULES_PATH,
    stage: str = "all",
    use_mongo: bool = False,
) -> Dict:
    pipeline = LogPipeline(server_type, rules_path, stage=stage, use_mongo=use_mongo)
    return pipeline.run(input_path, output_dir)


def run_pipeline_batch(
    *,
    input_path: str | Path,
    server_type: Optional[str],
    output_dir: str | Path,
    rules_path: str = DEFAULT_RULES_PATH,
    stage: str = "all",
    use_mongo: bool = False,
) -> Dict:
    path = Path(input_path)
    if path.is_file():
        return run_pipeline(
            input_path=path,
            server_type=server_type,
            output_dir=output_dir,
            rules_path=rules_path,
            stage=stage,
            use_mongo=use_mongo,
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
                stage=stage,
                use_mongo=use_mongo,
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
        "stage": stage,
        "counts": total_counts,
        "processed_files": len(runs),
        "skipped_files": len(skipped),
        "runs": runs,
        "skipped": skipped,
    }


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Web Server Log Parser + Rule-based Web Attack Detection (MongoDB & AI Ready)"
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
    parser.add_argument("--stage", default="all", choices=STAGE_CHOICES, help="Run one stage only or full pipeline")
    parser.add_argument("--mongo", action="store_true", help="Export results to MongoDB Atlas")
    return parser


def main() -> None:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    cli = build_cli()
    args = cli.parse_args()

    summary = run_pipeline_batch(
        input_path=args.input,
        server_type=args.server_type,
        output_dir=args.output_dir,
        rules_path=args.rules,
        stage=args.stage,
        use_mongo=args.mongo,
    )

    counts = summary.get("counts", {})
    print("[+] Pipeline finished")
    print(f"[+] Raw lines: {counts.get('raw_lines', 0)}")
    print(f"[+] Parsed logs: {counts.get('parsed_logs', 0)}")
    print(f"[+] Parse errors: {counts.get('parse_errors', 0)}")
    print(f"[+] Alerts: {counts.get('alerts', 0)}")
    
    if args.mongo:
        print("[+] Exported to MongoDB Atlas")
        
    collector_info = summary.get("collector", {})
    print(f"[+] Decode fallback records: {collector_info.get('decode_error_records', 0)}")
    
    if summary.get("mode") == "batch":
        print(f"[+] Processed files: {summary.get('processed_files', 0)}")
        print(f"[+] Skipped files: {summary.get('skipped_files', 0)}")
        skipped = summary.get("skipped", [])
        if skipped:
            print("[+] Skipped details:")
            for item in skipped:
                print(f"    - {item.get('input_path')}: {item.get('error')}")
                
    print(f"[+] Output dir: {summary.get('output_dir')}")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
