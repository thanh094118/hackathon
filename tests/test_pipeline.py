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
            "--server-type",
            "apache",
            "--output-dir",
            str(output_dir),
            "--rules",
            "data/labels/attack_patterns.yaml",
        ],
        check=True,
    )

    expected_files = [
        "raw_lines.jsonl",
        "parsed_logs.jsonl",
        "normalized_logs.jsonl",
        "normalized_logs.csv",
        "preprocessed_requests.jsonl",
        "features.csv",
        "alerts.jsonl",
        "alerts.csv",
        "report.md",
        "run_summary.json",
    ]
    for file_name in expected_files:
        assert (output_dir / file_name).exists(), file_name

    parsed = [
        json.loads(line)
        for line in (output_dir / "parsed_logs.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(parsed) == 2
    assert any(row["parse_status"] == "error" for row in parsed)
    assert all("event_id" in row for row in parsed)

    raw_rows = [
        json.loads(line)
        for line in (output_dir / "raw_lines.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert raw_rows
    assert all("encoding_used" in row for row in raw_rows)
    assert all("decode_error" in row for row in raw_rows)
    assert all("had_bom" in row for row in raw_rows)
    assert all("was_continuation_merged" in row for row in raw_rows)
    assert all("physical_line_start" in row for row in raw_rows)
    assert all("physical_line_end" in row for row in raw_rows)

    summary = json.loads((output_dir / "run_summary.json").read_text(encoding="utf-8"))
    assert summary["counts"]["raw_lines"] == 2
    assert summary["counts"]["parsed_logs"] == 2
    assert "collector" in summary
    assert "decode_error_records" in summary["collector"]
