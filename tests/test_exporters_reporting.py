import json
from pathlib import Path

from src.exporters.csv_exporter import CSVExporter
from src.exporters.jsonl_exporter import JSONLExporter
from src.reporting.report_generator import ReportGenerator


def test_jsonl_exporter_writes_records(tmp_path: Path):
    path = tmp_path / "rows.jsonl"
    JSONLExporter().export([{"a": 1}, {"a": 2}], path)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["a"] == 1


def test_csv_exporter_flattens_nested_data(tmp_path: Path):
    path = tmp_path / "rows.csv"
    CSVExporter(preferred_fieldnames=["line_number"]).export(
        [{"line_number": 1, "items": ["a", "b"]}],
        path,
    )
    text = path.read_text(encoding="utf-8")
    assert "line_number" in text
    assert '"[""a"", ""b""]"' in text


def test_report_generator_contains_summary_fields():
    summary = {
        "input_path": "input.log",
        "server_type": "apache",
        "rules_path": "rules.yaml",
        "output_dir": "out",
        "counts": {
            "raw_lines": 2,
            "parsed_logs": 2,
            "parse_errors": 1,
            "normalized_logs": 2,
            "preprocessed_requests": 2,
            "scored_records": 2,
            "alerts": 1,
        },
        "labels": {"benign": 1, "suspicious": 1, "malicious": 0},
        "top_attack_types": [("sqli", 1)],
        "top_matched_rule_ids": [("sqli_or_true", 1)],
    }
    report = ReportGenerator().generate(summary, alerts=[{"source_ip": "1.1.1.1"}])
    assert "Web Attack Detection Report" in report
    assert "Raw lines" in report
    assert "sqli_or_true" in report
