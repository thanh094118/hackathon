from pathlib import Path

from src.collector.file_collector import FileCollector


def test_read_flow_handles_bom_and_continuation_lines(tmp_path: Path):
    log_path = tmp_path / "access1.log"
    log_path.write_bytes(
        b"\xef\xbb\xbf127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "
        b"\"GET /index HTTP/1.1\" 200 10 \"-\" \"ua\"\n"
        b"  <broken continuation>\n"
        b"10.0.0.2 - - [10/Oct/2000:13:55:37 +0000] "
        b"\"GET /ok HTTP/1.1\" 200 20 \"-\" \"ua2\"\n"
    )

    lines = FileCollector(str(log_path)).read_all()
    assert len(lines) == 2
    assert "\\n  <broken continuation>" in lines[0]
    assert lines[0].startswith("127.0.0.1")


def test_read_flow_does_not_merge_non_indented_lines(tmp_path: Path):
    log_path = tmp_path / "access2.log"
    log_path.write_bytes(
        b"127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "
        b"\"GET /a HTTP/1.1\" 200 10 \"-\" \"ua\"\n"
        b"Injected-Header: abc\n"
        b"example-host - - [10/Oct/2000:13:55:37 +0000] "
        b"\"GET /b HTTP/1.1\" 200 20 \"-\" \"ua2\"\n"
        b"::ffff:1.2.3.4 - - [10/Oct/2000:13:55:38 +0000] "
        b"\"GET /c HTTP/1.1\" 200 30 \"-\" \"ua3\"\n"
        b"- - - [10/Oct/2000:13:55:39 +0000] "
        b"\"GET /d HTTP/1.1\" 200 40 \"-\" \"ua4\"\n"
    )

    lines = FileCollector(str(log_path)).read_all()
    assert len(lines) == 5
    assert lines[1] == "Injected-Header: abc"
    assert lines[2].startswith("example-host")
    assert lines[3].startswith("::ffff:1.2.3.4")
    assert lines[4].startswith("- - -")


def test_collect_flow_copies_file_byte_exactly(tmp_path: Path):
    input_root = tmp_path / "input"
    apache_dir = input_root / "Apache"
    apache_dir.mkdir(parents=True, exist_ok=True)
    raw_bytes = (
        b"127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "
        b"\"GET /index HTTP/1.1\" 200 10 \"-\" \"ua\"\n"
    )
    log_path = apache_dir / "access1.log"
    log_path.write_bytes(raw_bytes)

    output_root = tmp_path / "outputs"
    jobs = FileCollector(str(input_root)).collect_jobs(str(output_root))
    assert len(jobs) == 1

    copied_path = jobs[0].output_txt_path
    assert copied_path.exists()
    assert copied_path.read_bytes() == raw_bytes


def test_read_flow_records_include_optional_metadata(tmp_path: Path):
    log_path = tmp_path / "access3.log"
    log_path.write_bytes(
        b"\xef\xbb\xbf127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "
        b"\"GET /x HTTP/1.1\" 200 10 \"-\" \"ua\"\n"
        b"\tcontinuation\n"
    )
    records = FileCollector(str(log_path)).read_records()
    assert len(records) == 1
    first = records[0]
    assert first["encoding_used"] in {"utf-8", "latin-1"}
    assert first["had_bom"] is True
    assert first["was_continuation_merged"] is True
    assert first["physical_line_start"] == 1
    assert first["physical_line_end"] == 2


def test_collect_flow_warning_log_is_appended_not_overwritten(tmp_path: Path):
    input_root = tmp_path / "input"
    nginx_dir = input_root / "Nginx"
    nginx_dir.mkdir(parents=True, exist_ok=True)
    log_path = nginx_dir / "access9.log"
    log_path.write_bytes(b"\xff\xfe\xfd bad bytes\n")

    output_root = tmp_path / "outputs"
    collector = FileCollector(str(input_root))
    collector.collect_jobs(str(output_root))
    collector.collect_jobs(str(output_root))

    warning_file = output_root / "Nginx" / "access9" / "log.txt"
    text = warning_file.read_text(encoding="utf-8")
    assert text.count("Non-UTF-8 byte sequences detected") >= 2
