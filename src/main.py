from __future__ import annotations

import hashlib
import argparse
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.collector.file_collector import FileCollector
from src.converter import convert_flow
from src.detection.rule_detector import RuleDetector
from src.exporters.csv_exporter import CSVExporter
from src.exporters.jsonl_exporter import JSONLExporter
from src.exporters.markdown_exporter import MarkdownExporter
from src.features.feature_extractor import FeatureExtractor
from src.normalizer.normalizer import Normalizer
from src.parser.apache_parser import ApacheParser
from src.parser.iis_parser import IISParser
from src.parser.nginx_parser import NginxParser
from src.ml.inference import MLPredictor
from src.preprocessor.request_preprocessor import RequestPreprocessor
from src.reporting.postprocessor import PostProcessor
from src.reporting.report_generator import ReportGenerator
from src.scoring.risk_engine import RiskEngine


SUPPORTED_INPUT_SUFFIXES = {".log", ".txt", ".csv", ".json", ".jsonl"}
SERVER_TYPES = {"apache", "nginx", "iis"}


def build_cli() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(description="Run the web attack detection pipeline")
	parser.add_argument("--input", required=True, help="Input file or folder path")
	parser.add_argument("--output-dir", required=True, help="Output directory")
	parser.add_argument("--rules", default="src/rules/attack_patterns.yaml", help="Rule YAML path")
	parser.add_argument("--ml-enable", action="store_true", help="Enable ML inference if model artifacts are available")
	parser.add_argument("--ml-model-dir", default="models/ml", help="Directory containing trained ML artifacts")
	parser.add_argument("--ml-threshold", type=float, default=0.5, help="Binary attack threshold for ML inference")
	parser.add_argument(
		"--server-type",
		choices=sorted(SERVER_TYPES),
		default=None,
		help="Optional server type override; defaults to apache for log-like inputs",
	)
	return parser


def main() -> None:
	logging.basicConfig(level=logging.INFO, format="%(message)s")
	args = build_cli().parse_args()

	input_path = Path(args.input)
	output_dir = Path(args.output_dir)
	output_dir.mkdir(parents=True, exist_ok=True)

	summaries = run_pipeline(
		input_path=input_path,
		output_dir=output_dir,
		rules_path=Path(args.rules),
		ml_enable=bool(args.ml_enable),
		ml_model_dir=Path(args.ml_model_dir),
		ml_threshold=float(args.ml_threshold),
		server_type=args.server_type,
	)

	for summary in summaries:
		logging.info(
			"[+] Completed %s: %s alerts from %s raw lines",
			summary["output_dir"],
			summary["counts"]["alerts"],
			summary["counts"]["raw_lines"],
		)


def run_pipeline(
	*,
	input_path: Path,
	output_dir: Path,
	rules_path: Path,
	ml_enable: bool = False,
	ml_model_dir: Optional[Path] = None,
	ml_threshold: float = 0.5,
	server_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
	if not input_path.exists():
		raise FileNotFoundError(f"Input path not found: {input_path}")

	if input_path.is_dir():
		input_files = _discover_input_files(input_path)
		if not input_files:
			raise ValueError(f"No supported input files found under: {input_path}")
		summaries: List[Dict[str, Any]] = []
		for file_path in input_files:
			run_id = _run_id_for_path(input_path, file_path)
			run_output_dir = output_dir / run_id
			summaries.append(
				_run_single_pipeline(
					input_path=file_path,
					run_output_dir=run_output_dir,
					rules_path=rules_path,
					ml_enable=ml_enable,
					ml_model_dir=ml_model_dir,
					ml_threshold=ml_threshold,
					server_type=server_type,
				)
			)
		return summaries

	return [
		_run_single_pipeline(
			input_path=input_path,
			run_output_dir=output_dir,
			rules_path=rules_path,
			ml_enable=ml_enable,
			ml_model_dir=ml_model_dir,
			ml_threshold=ml_threshold,
			server_type=server_type,
		)
	]


def _run_single_pipeline(
	*,
	input_path: Path,
	run_output_dir: Path,
	rules_path: Path,
	ml_enable: bool,
	ml_model_dir: Optional[Path],
	ml_threshold: float,
	server_type: Optional[str],
) -> Dict[str, Any]:
	run_output_dir.mkdir(parents=True, exist_ok=True)

	detected_server_type = _resolve_server_type(input_path, server_type)
	prefix = f"{detected_server_type}_{input_path.stem}"

	raw_records = _load_raw_records(input_path, detected_server_type)
	raw_lines = [record["line"] for record in raw_records]

	parser = _build_parser(detected_server_type)
	parsed_logs = list(parser.parse_lines(raw_lines))

	normalizer = Normalizer()
	normalized_logs = [normalizer.normalize(record) for record in parsed_logs]

	preprocessor = RequestPreprocessor()
	preprocessed_requests = [preprocessor.preprocess(record) for record in normalized_logs]

	feature_extractor = FeatureExtractor()
	feature_records = [feature_extractor.enrich(record) for record in preprocessed_requests]

	detector = RuleDetector(rules_path=rules_path, enrich=False)
	risk_engine = RiskEngine()

	scored_records: List[Dict[str, Any]] = []
	alerts: List[Dict[str, Any]] = []
	for record in feature_records:
		detection = detector.detect(record)
		enriched = dict(record)
		enriched.update(detection)
		scored = risk_engine.score(enriched)
		enriched.update(scored)
		scored_records.append(enriched)
		if enriched.get("should_alert"):
			alerts.append(enriched)

	ml_predictions: List[Dict[str, Any]] = []
	if ml_enable:
		ml_predictions = _apply_ml_predictions(scored_records, ml_model_dir, ml_threshold)
		if ml_predictions:
			scored_records = ml_predictions
			alerts = [record for record in scored_records if record.get("should_alert")]

	summary = PostProcessor().build_summary(
		input_path=str(input_path),
		server_type=detected_server_type,
		output_dir=str(run_output_dir),
		rules_path=str(rules_path),
		raw_lines=raw_records,
		parsed_logs=parsed_logs,
		normalized_logs=normalized_logs,
		preprocessed_requests=preprocessed_requests,
		scored_records=scored_records,
		ml_predictions=ml_predictions,
		alerts=alerts,
	)
	summary["collector"] = {
		"decode_error_records": sum(1 for record in raw_records if record.get("decode_error")),
		"had_bom_records": sum(1 for record in raw_records if record.get("had_bom")),
		"continuation_merged_records": sum(1 for record in raw_records if record.get("was_continuation_merged")),
	}

	_export_stage_outputs(
		run_output_dir=run_output_dir,
		prefix=prefix,
		raw_records=raw_records,
		parsed_logs=parsed_logs,
		normalized_logs=normalized_logs,
		preprocessed_requests=preprocessed_requests,
		feature_records=feature_records,
		ml_predictions=ml_predictions,
		alerts=alerts,
		summary=summary,
	)

	return summary


def _export_stage_outputs(
	*,
	run_output_dir: Path,
	prefix: str,
	raw_records: List[Dict[str, Any]],
	parsed_logs: List[Dict[str, Any]],
	normalized_logs: List[Dict[str, Any]],
	preprocessed_requests: List[Dict[str, Any]],
	feature_records: List[Dict[str, Any]],
	ml_predictions: List[Dict[str, Any]],
	alerts: List[Dict[str, Any]],
	summary: Dict[str, Any],
) -> None:
	collector_dir = run_output_dir / "collector_results"
	parser_dir = run_output_dir / "parser_results"
	normalizer_dir = run_output_dir / "normalizer_results"
	preprocessor_dir = run_output_dir / "preprocessor_results"
	feature_dir = run_output_dir / "feature_results"
	ml_dir = run_output_dir / "ml_results"
	detector_dir = run_output_dir / "detector_results"
	report_dir = run_output_dir / "report"

	JSONLExporter().export(raw_records, collector_dir / f"{prefix}_raw_lines.jsonl")
	JSONLExporter().export(parsed_logs, parser_dir / f"{prefix}_parsed_logs.jsonl")
	JSONLExporter().export(normalized_logs, normalizer_dir / f"{prefix}_normalized_logs.jsonl")
	CSVExporter().export(normalized_logs, normalizer_dir / f"{prefix}_normalized_logs.csv")
	JSONLExporter().export(preprocessed_requests, preprocessor_dir / f"{prefix}_preprocessed_requests.jsonl")
	CSVExporter().export(feature_records, feature_dir / f"{prefix}_features.csv")
	if ml_predictions:
		JSONLExporter().export(ml_predictions, ml_dir / f"{prefix}_ml_predictions.jsonl")
		CSVExporter().export(ml_predictions, ml_dir / f"{prefix}_ml_predictions.csv")
	JSONLExporter().export(alerts, detector_dir / f"{prefix}_alerts.jsonl")
	CSVExporter().export(alerts, detector_dir / f"{prefix}_alerts.csv")

	MarkdownExporter().export(
		ReportGenerator().generate(summary, alerts),
		report_dir / f"{prefix}_report.md",
	)
	JSONLExporter().export([summary], report_dir / f"{prefix}_run_summary.json")


def _apply_ml_predictions(
	records: List[Dict[str, Any]],
	ml_model_dir: Optional[Path],
	ml_threshold: float,
) -> List[Dict[str, Any]]:
	if not ml_model_dir:
		logging.info("[!] ML enabled but no model directory was provided; skipping ML stage")
		return records

	try:
		predictor = MLPredictor(model_dir=ml_model_dir, threshold=ml_threshold)
	except FileNotFoundError as exc:
		logging.info("[!] ML artifacts not found at %s: %s", ml_model_dir, exc)
		return records

	return predictor.predict_records(records)


def _discover_input_files(input_root: Path) -> List[Path]:
	return [
		path
		for path in sorted(input_root.rglob("*"))
		if path.is_file() and path.suffix.lower() in SUPPORTED_INPUT_SUFFIXES
	]


def _run_id_for_path(input_root: Path, file_path: Path) -> str:
	try:
		relative = file_path.relative_to(input_root).with_suffix("")
		return "__".join(relative.parts)
	except ValueError:
		return file_path.stem


def _resolve_server_type(input_path: Path, server_type: Optional[str]) -> str:
	if server_type:
		return server_type.lower()

	if input_path.suffix.lower() in {".csv", ".json", ".jsonl"}:
		return "apache"

	try:
		with input_path.open("r", encoding="utf-8", errors="ignore") as handle:
			for _ in range(20):
				line = handle.readline()
				if not line:
					break
				stripped = line.strip().lower()
				if not stripped:
					continue
				if stripped.startswith("#fields:") or "cs-method" in stripped or "w3c" in stripped:
					return "iis"
				if "nginx" in stripped:
					return "nginx"
				if "apache" in stripped:
					return "apache"
	except OSError:
		pass

	return "apache"


def _build_parser(server_type: str):
	server = server_type.lower()
	if server == "nginx":
		return NginxParser()
	if server == "iis":
		return IISParser()
	return ApacheParser()


def _load_raw_records(input_path: Path, server_type: str) -> List[Dict[str, Any]]:
	suffix = input_path.suffix.lower()
	if suffix in {".csv", ".json", ".jsonl"}:
		return _load_structured_input_as_raw_records(input_path, server_type)

	collector = FileCollector(str(input_path))
	records = collector.read_records()
	for record in records:
		line = str(record.get("line", ""))
		record["raw_log"] = line
		record["event_id"] = _build_event_id(server_type, int(record.get("physical_line_start", 1)), line)
	return records


def _load_structured_input_as_raw_records(input_path: Path, server_type: str) -> List[Dict[str, Any]]:
	raw_records: List[Dict[str, Any]] = []
	line_number = 0

	for item in convert_flow._iter_input_items(input_path):
		for line in convert_flow._to_raw_log_lines(item):
			text = str(line).strip()
			if not text:
				continue
			line_number += 1
			raw_records.append(
				{
					"line": text,
					"raw_log": text,
					"encoding_used": "utf-8",
					"decode_error": False,
					"had_bom": False,
					"was_continuation_merged": False,
					"physical_line_start": line_number,
					"physical_line_end": line_number,
					"event_id": _build_event_id(server_type, line_number, text),
				}
			)

	return raw_records


def _build_event_id(server_type: str, line_number: int, raw_log: str) -> str:
	digest = hashlib.sha1(str(raw_log).encode("utf-8", errors="ignore")).hexdigest()[:12]
	return f"{server_type}:{line_number}:{digest}"


if __name__ == "__main__":
	main()
