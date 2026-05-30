from pathlib import Path

import pytest

from src.collector.file_collector import FileCollector
from src.collector.read_flow import AccessLogReadFlow


# ============================================================
# READ FLOW TESTS
# Mục tiêu:
# - Kiểm tra đọc file ở chế độ binary.
# - Decode UTF-8 trước, fallback latin-1 nếu lỗi.
# - Strip UTF-8 BOM ở dòng đầu tiên.
# - Chuẩn hóa line ending.
# - Bỏ dòng rỗng.
# - Chỉ merge continuation line nếu bắt đầu bằng space/tab.
# - Ghi metadata cho từng logical record.
# ============================================================


def test_read_flow_handles_utf8_bom_only_on_first_line(tmp_path: Path):
    """
    Test:
    - Nếu file có UTF-8 BOM ở dòng đầu tiên thì Collector phải bỏ BOM.
    - Nếu BOM xuất hiện ở dòng sau thì không được strip vì đó không còn là BOM đầu file.

    Ý nghĩa:
    - Tránh parser downstream nhận dòng đầu bị prefix bằng ký tự \ufeff.
    - Đồng thời không tự ý sửa nội dung các dòng sau.
    """
    log_path = tmp_path / "access.log"
    log_path.write_bytes(
        b"\xef\xbb\xbf127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "
        b"\"GET /a HTTP/1.1\" 200 10 \"-\" \"ua\"\n"
        b"\xef\xbb\xbf10.0.0.2 - - [10/Oct/2000:13:55:37 +0000] "
        b"\"GET /b HTTP/1.1\" 200 20 \"-\" \"ua2\"\n"
    )

    records = FileCollector(str(log_path)).read_records()

    assert len(records) == 2
    assert records[0]["line"].startswith("127.0.0.1")
    assert "had_utf8_bom" in records[0]["flags"]

    # BOM ở dòng 2 không bị strip vì không phải BOM đầu file.
    assert records[1]["line"].startswith("\ufeff10.0.0.2")
    assert "had_utf8_bom" not in records[1]["flags"]


def test_read_flow_normalizes_lf_crlf_and_cr_line_endings(tmp_path: Path):
    """
    Test:
    - File có nhiều kiểu xuống dòng: LF, CRLF, CR.
    - Output logical line không được còn ký tự \\n hoặc \\r ở cuối.

    Ý nghĩa:
    - Log có thể đến từ Linux, Windows hoặc nguồn copy khác nhau.
    - Parser downstream nên nhận line đã sạch line ending.
    """
    log_path = tmp_path / "access.log"
    log_path.write_bytes(
        b"127.0.0.1 - - [date] \"GET /lf HTTP/1.1\" 200 1 \"-\" \"ua\"\n"
        b"127.0.0.2 - - [date] \"GET /crlf HTTP/1.1\" 200 2 \"-\" \"ua\"\r\n"
        b"127.0.0.3 - - [date] \"GET /cr HTTP/1.1\" 200 3 \"-\" \"ua\"\r"
    )

    lines = FileCollector(str(log_path)).read_all()

    assert len(lines) == 3
    assert all(not line.endswith("\n") for line in lines)
    assert all(not line.endswith("\r") for line in lines)


def test_read_flow_splits_cr_only_physical_lines(tmp_path: Path):
    """
    Test:
    - File sử dụng CR-only giữa các dòng vật lý (legacy style).
    - Reader phải tách được thành nhiều logical line thay vì gom thành một dòng.
    """
    log_path = tmp_path / "access.log"
    log_path.write_bytes(
        b"127.0.0.1 - - [date] \"GET /a HTTP/1.1\" 200 1 \"-\" \"ua\"\r"
        b"127.0.0.2 - - [date] \"GET /b HTTP/1.1\" 200 2 \"-\" \"ua2\"\r"
        b"127.0.0.3 - - [date] \"GET /c HTTP/1.1\" 200 3 \"-\" \"ua3\""
    )

    lines = FileCollector(str(log_path)).read_all()

    assert len(lines) == 3
    assert lines[0].startswith("127.0.0.1")
    assert lines[1].startswith("127.0.0.2")
    assert lines[2].startswith("127.0.0.3")


def test_read_flow_skips_empty_and_whitespace_only_lines(tmp_path: Path):
    """
    Test:
    - Dòng rỗng, dòng chỉ có space, dòng chỉ có tab đều bị bỏ qua.

    Ý nghĩa:
    - Tránh tạo record rác.
    - Giữ output chỉ gồm các dòng có nội dung thực sự.
    """
    log_path = tmp_path / "access.log"
    log_path.write_bytes(
        b"\n"
        b"   \n"
        b"\t\n"
        b"127.0.0.1 - - [date] \"GET /ok HTTP/1.1\" 200 1 \"-\" \"ua\"\n"
        b"\r\n"
    )

    lines = FileCollector(str(log_path)).read_all()

    assert lines == [
        '127.0.0.1 - - [date] "GET /ok HTTP/1.1" 200 1 "-" "ua"'
    ]


def test_read_flow_merges_space_and_tab_continuation_lines(tmp_path: Path):
    """
    Test:
    - Dòng bắt đầu bằng space được merge vào dòng log trước.
    - Dòng bắt đầu bằng tab cũng được merge vào dòng log trước.
    - Metadata phải ghi nhận có merge continuation.

    Ý nghĩa:
    - Đây là rule mới an toàn hơn heuristic cũ.
    - Chỉ dòng có indent rõ ràng mới được xem là continuation.
    """
    log_path = tmp_path / "access.log"
    log_path.write_bytes(
        b"127.0.0.1 - - [date] \"GET /a HTTP/1.1\" 200 1 \"-\" \"ua\"\n"
        b"  continued payload\n"
        b"\tcontinued tab payload\n"
        b"10.0.0.2 - - [date] \"GET /b HTTP/1.1\" 200 2 \"-\" \"ua2\"\n"
    )

    records = FileCollector(str(log_path)).read_records()

    assert len(records) == 2
    assert records[0]["line"] == (
        '127.0.0.1 - - [date] "GET /a HTTP/1.1" 200 1 "-" "ua"'
        "\\n  continued payload"
        "\\n\tcontinued tab payload"
    )
    assert "continuation_merged" in records[0]["flags"]
    assert records[0]["physical_line_range"] == [1, 3]


def test_read_flow_does_not_merge_non_indented_injection_like_lines(tmp_path: Path):
    """
    Test:
    - Các dòng giống payload/injection nhưng không có indent thì không được merge.
    - Ví dụ: Injected-Header, <script>, JSON-like line.

    Ý nghĩa:
    - Collector không nên suy diễn quá mạnh.
    - Newline injection không indent nên để Parser/Detector xử lý sau.
    """
    log_path = tmp_path / "access.log"
    log_path.write_bytes(
        b"127.0.0.1 - - [date] \"GET /a HTTP/1.1\" 200 1 \"-\" \"ua\"\n"
        b"Injected-Header: abc\n"
        b"<script>alert(1)</script>\n"
        b"{json: true}\n"
        b"10.0.0.2 - - [date] \"GET /b HTTP/1.1\" 200 2 \"-\" \"ua2\"\n"
    )

    lines = FileCollector(str(log_path)).read_all()

    assert len(lines) == 5
    assert lines[1] == "Injected-Header: abc"
    assert lines[2] == "<script>alert(1)</script>"
    assert lines[3] == "{json: true}"


def test_read_flow_does_not_merge_valid_unusual_log_prefixes(tmp_path: Path):
    """
    Test:
    - Các log hợp lệ nhưng có prefix không phổ biến vẫn không bị merge nhầm.
    - Bao gồm:
      + IPv6-mapped IPv4: ::ffff:1.2.3.4
      + Dòng bắt đầu bằng dấu -
      + Hostname
      + Prefix trong ngoặc vuông

    Ý nghĩa:
    - Khóa lại bug của heuristic cũ:
      return not re.match(...)
    - Heuristic cũ có thể nhầm các prefix lạ thành continuation.
    """
    log_path = tmp_path / "access.log"
    log_path.write_bytes(
        b"::ffff:1.2.3.4 - - [date] \"GET /ipv6 HTTP/1.1\" 200 1 \"-\" \"ua\"\n"
        b"- - - [date] \"GET /dash HTTP/1.1\" 200 2 \"-\" \"ua\"\n"
        b"example-host - - [date] \"GET /host HTTP/1.1\" 200 3 \"-\" \"ua\"\n"
        b"[custom-prefix] 127.0.0.1 - - \"GET /bracket HTTP/1.1\" 200\n"
    )

    lines = FileCollector(str(log_path)).read_all()

    assert len(lines) == 4
    assert lines[0].startswith("::ffff:1.2.3.4")
    assert lines[1].startswith("- - -")
    assert lines[2].startswith("example-host")
    assert lines[3].startswith("[custom-prefix]")


def test_read_flow_latin1_fallback_does_not_crash(tmp_path: Path):
    """
    Test:
    - Một dòng có byte không decode được bằng UTF-8.
    - Collector phải fallback sang latin-1 thay vì crash.
    - Record phải có flag decode fallback latin-1.

    Ý nghĩa:
    - File access.log thực tế có thể chứa byte bẩn.
    - Pipeline không nên chết ở Collector.
    """
    log_path = tmp_path / "access.log"
    log_path.write_bytes(
        b"127.0.0.1 - - [date] \"GET /ok HTTP/1.1\" 200 1 \"-\" \"ua\"\n"
        b"10.0.0.2 - - [date] \"GET /\xff HTTP/1.1\" 200 2 \"-\" \"ua2\"\n"
    )

    records = FileCollector(str(log_path)).read_records()

    assert len(records) == 2
    assert "decode_fallback_latin1" not in records[0]["flags"]
    assert "decode_fallback_latin1" in records[1]["flags"]
    assert "ÿ" in records[1]["line"]


def test_read_flow_continuation_propagates_decode_fallback_flag(tmp_path: Path):
    """
    Test:
    - Dòng continuation chứa byte bẩn thì logical record phải có flag decode fallback.

    Ý nghĩa:
    - Metadata phải phản ánh toàn bộ logical record.
    """
    log_path = tmp_path / "access.log"
    log_path.write_bytes(
        b"127.0.0.1 - - [date] \"GET /ok HTTP/1.1\" 200 1 \"-\" \"ua\"\n"
        b"  continuation with bad byte \xff\n"
    )

    records = FileCollector(str(log_path)).read_records()

    assert len(records) == 1
    assert "decode_fallback_latin1" in records[0]["flags"]
    assert "continuation_merged" in records[0]["flags"]


def test_read_flow_validate_missing_file_raises(tmp_path: Path):
    """
    Test:
    - Input path không tồn tại thì raise FileNotFoundError.

    Ý nghĩa:
    - Fail sớm với lỗi rõ ràng.
    """
    missing = tmp_path / "missing.log"

    with pytest.raises(FileNotFoundError):
        FileCollector(str(missing)).read_all()


def test_read_flow_validate_directory_raises(tmp_path: Path):
    """
    Test:
    - Read flow chỉ nhận file, không nhận directory.

    Ý nghĩa:
    - Tránh nhầm giữa read một file log và collect cả thư mục.
    """
    with pytest.raises(ValueError):
        FileCollector(str(tmp_path)).read_all()


def test_access_log_read_flow_internal_continuation_rule_is_indent_only():
    """
    Test:
    - Unit test trực tiếp rule _is_continuation_line().
    - Chỉ space/tab đầu dòng mới là continuation.
    - Các prefix khác không được xem là continuation.

    Ý nghĩa:
    - Khóa behavior quan trọng nhất của fix heuristic.
    - Nếu sau này ai sửa lại heuristic thô cũ, test này sẽ fail.
    """
    assert AccessLogReadFlow._is_continuation_line(" continuation") is True
    assert AccessLogReadFlow._is_continuation_line("\tcontinuation") is True

    assert AccessLogReadFlow._is_continuation_line("Injected-Header: abc") is False
    assert AccessLogReadFlow._is_continuation_line("<script>") is False
    assert AccessLogReadFlow._is_continuation_line("::ffff:1.2.3.4 - -") is False
    assert AccessLogReadFlow._is_continuation_line("- - - [date]") is False
