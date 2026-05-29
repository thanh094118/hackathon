import json
import subprocess
import sys
from pathlib import Path


def test_pipeline_cli_generates_expected_outputs(tmp_path: Path):
    input_log = tmp_path / "access.log"
    input_log.write_text(
        '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /index.php?id=1%20OR%201=1 HTTP/1.1" 200 123 "-" "sqlmap/1.0"\n'
        "not a valid access line\n",
        encoding="utf-8",
    )
    output_dir = tmp_path / "run_outputs"

    subprocess.run(
        [
            sys.executable,
            "-m",
            "src.main",
            "--input",
            str(input_log),
            "--output-dir",
            str(output_dir),
            "--rules",
            "src/rules/attack_patterns.yaml",
        ],
        check=True,
    )

    expected_files = [
        "collector_results/apache_access_raw_lines.jsonl",
        "parser_results/apache_access_parsed_logs.jsonl",
        "normalizer_results/apache_access_normalized_logs.jsonl",
        "normalizer_results/apache_access_normalized_logs.csv",
        "preprocessor_results/apache_access_preprocessed_requests.jsonl",
        "feature_results/apache_access_features.csv",
        "detector_results/apache_access_alerts.jsonl",
        "detector_results/apache_access_alerts.csv",
        "report/apache_access_report.md",
        "report/apache_access_run_summary.json",
    ]
    for file_name in expected_files:
        assert (output_dir / file_name).exists(), file_name

    parsed = [
        json.loads(line)
        for line in (output_dir / "parser_results/apache_access_parsed_logs.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(parsed) == 2
    assert any(row["parse_status"] == "error" for row in parsed)
    assert all("event_id" in row for row in parsed)

    raw_rows = [
        json.loads(line)
        for line in (output_dir / "collector_results/apache_access_raw_lines.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert raw_rows
    assert all("encoding_used" in row for row in raw_rows)
    assert all("decode_error" in row for row in raw_rows)
    assert all("had_bom" in row for row in raw_rows)
    assert all("was_continuation_merged" in row for row in raw_rows)
    assert all("physical_line_start" in row for row in raw_rows)
    assert all("physical_line_end" in row for row in raw_rows)
    assert [row["event_id"] for row in raw_rows] == [row["event_id"] for row in parsed]

    summary = json.loads((output_dir / "report/apache_access_run_summary.json").read_text(encoding="utf-8"))
    assert summary["counts"]["raw_lines"] == 2
    assert summary["counts"]["parsed_logs"] == 2
    assert "collector" in summary
    assert "decode_error_records" in summary["collector"]
    assert summary["server_type"] == "apache"


def test_pipeline_cli_accepts_folder_input(tmp_path: Path):
    input_dir = tmp_path / "inputs"
    input_dir.mkdir()
    (input_dir / "a.log").write_text(
        '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /ok HTTP/1.1" 200 10 "-" "ua"\n',
        encoding="utf-8",
    )
    (input_dir / "bad.log").write_text("not a valid access line\n", encoding="utf-8")

    output_dir = tmp_path / "batch_outputs"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "src.main",
            "--input",
            str(input_dir),
            "--output-dir",
            str(output_dir),
            "--rules",
            "src/rules/attack_patterns.yaml",
        ],
        check=True,
    )

    summary_files = list(output_dir.rglob("*_run_summary.json"))
    assert summary_files, "Expected at least one run summary file in batch output"
