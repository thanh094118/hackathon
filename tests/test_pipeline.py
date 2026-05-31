import json
import os
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
            "--debug-local",
        ],
        env={"PIPELINE_TESTING": "true", **os.environ},
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
    assert all("flags" in row for row in raw_rows)
    assert all(isinstance(row["flags"], list) for row in raw_rows)
    assert all("physical_line_range" in row for row in raw_rows)
    assert all(isinstance(row["physical_line_range"], list) and len(row["physical_line_range"]) == 2 for row in raw_rows)
    assert all("parse_error" not in row for row in raw_rows)
    assert all("error_message" not in row for row in raw_rows)
    assert [row["event_id"] for row in raw_rows] == [row["event_id"] for row in parsed]

    summary = json.loads((output_dir / "report/apache_access_run_summary.json").read_text(encoding="utf-8"))
    assert summary["counts"]["raw_lines"] == 2
    assert summary["counts"]["parsed_logs"] == 2
    assert "collector" in summary
    assert "decode_error_records" in summary["collector"]
    assert summary["server_type"] == "apache"
    assert summary["hybrid_detection"]["method"] == "hybrid"
    assert summary["ml"]["enabled"] is True


    alerts = [
        json.loads(line)
        for line in (output_dir / "detector_results/apache_access_alerts.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert alerts
    assert all(row["detection_method"] == "hybrid" for row in alerts)
    assert any("rules" in row["detection_sources"] for row in alerts)


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
            "--debug-local",
        ],
        env={"PIPELINE_TESTING": "true", **os.environ},
        check=True,
    )

    summary_files = list(output_dir.rglob("*_run_summary.json"))
    assert summary_files, "Expected at least one run summary file in batch output"


def test_pipeline_cli_accepts_capec_csv_input(tmp_path: Path):
    input_csv = tmp_path / "data_capec_multilabel.csv"
    input_csv.write_text(
        "timestamp,src_ip,src_port,dst_ip,dst_port,request_http_method,request_http_request,request_http_protocol,request_user_agent,request_referer,request_host,request_origin,request_cookie,request_content_type,request_accept,request_accept_language,request_accept_encoding,request_do_not_track,request_connection,request_body,response_http_protocol,response_http_status_code,response_http_status_message,response_content_length,000 - Normal,272 - Protocol Manipulation,242 - Code Injection,88 - OS Command Injection,126 - Path Traversal,66 - SQL Injection,16 - Dictionary-based Password Attack,310 - Scanning for Vulnerable Software,153 - Input Data Manipulation,248 - Command Injection,274 - HTTP Verb Tampering,194 - Fake the Source of Data,34 - HTTP Response Splitting,33 - HTTP Request Smuggling\n"
        "17/Jul/2020:12:23:34 +0100,172.26.0.1,55894,172.26.0.4,80,GET,/,HTTP/1.1,Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.130 Safari/537.36,,test-site.com,,,,*/*,,\"gzip, deflate\",,keep-alive,,HTTP/1.1,200,OK,25174,1,0,0,0,0,0,0,0,0,0,0,0,0,0\n",
        encoding="utf-8",
    )

    output_dir = tmp_path / "capec_outputs"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "src.main",
            "--input",
            str(input_csv),
            "--output-dir",
            str(output_dir),
            "--rules",
            "src/rules/attack_patterns.yaml",
            "--debug-local",
        ],
        env={"PIPELINE_TESTING": "true", **os.environ},
        check=True,
    )

    expected_files = [
        "collector_results/apache_data_capec_multilabel_raw_lines.jsonl",
        "parser_results/apache_data_capec_multilabel_parsed_logs.jsonl",
        "normalizer_results/apache_data_capec_multilabel_normalized_logs.jsonl",
        "normalizer_results/apache_data_capec_multilabel_normalized_logs.csv",
        "preprocessor_results/apache_data_capec_multilabel_preprocessed_requests.jsonl",
        "feature_results/apache_data_capec_multilabel_features.csv",
        "detector_results/apache_data_capec_multilabel_alerts.jsonl",
        "detector_results/apache_data_capec_multilabel_alerts.csv",
        "report/apache_data_capec_multilabel_report.md",
        "report/apache_data_capec_multilabel_run_summary.json",
    ]
    for file_name in expected_files:
        assert (output_dir / file_name).exists(), file_name

    summary = json.loads((output_dir / "report/apache_data_capec_multilabel_run_summary.json").read_text(encoding="utf-8"))
    assert summary["counts"]["raw_lines"] == 1
    assert summary["counts"]["parsed_logs"] == 1
    assert summary["server_type"] == "apache"


def test_pipeline_cli_no_local_outputs_by_default(tmp_path: Path):
    input_log = tmp_path / "access.log"
    input_log.write_text(
        '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /index.php?id=1 HTTP/1.1" 200 123 "-" "sqlmap"\n',
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
        env={"PIPELINE_TESTING": "true", **os.environ},
        check=True,
    )

    # By default, files (like report or collector_results) should NOT exist.
    # We check that the directory is empty or does not contain expected files.
    # Note that run_output_dir is created, but no files are exported.
    unexpected_files = [
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
    for file_name in unexpected_files:
        assert not (output_dir / file_name).exists(), f"File should not exist: {file_name}"

