from pathlib import Path

from src.collector.file_collector import FileCollector


def test_read_flow_handles_bom_and_continuation_lines(tmp_path: Path):
    log_path = tmp_path / "access1.log"
    log_path.write_bytes(
        b"\xef\xbb\xbf127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "
        b"\"GET /index HTTP/1.1\" 200 10 \"-\" \"ua\"\n"
        b"<broken continuation>\n"
        b"10.0.0.2 - - [10/Oct/2000:13:55:37 +0000] "
        b"\"GET /ok HTTP/1.1\" 200 20 \"-\" \"ua2\"\n"
    )

    lines = FileCollector(str(log_path)).read_all()
    assert len(lines) == 2
    assert "\\n<broken continuation>" in lines[0]
    assert lines[0].startswith("127.0.0.1")


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
