from pathlib import Path

from src.converter.convert_flow import convert_file


def _read_lines(path: Path):
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_convert_csv_new_format(tmp_path: Path):
    input_path = tmp_path / "flow.csv"
    input_path.write_text(
        "timestamp,src_ip,src_port,dst_ip,dst_port,request_http_method,request_http_request,request_http_protocol,request_user_agent,request_referer,request_host,request_origin,request_cookie,request_content_type,request_accept,request_accept_language,request_accept_encoding,request_do_not_track,request_connection,request_body,response_http_protocol,response_http_status_code,response_http_status_message,response_content_length,000 - Normal\n"
        "17/Jul/2020:12:23:34 +0100,172.26.0.1,55894,172.26.0.4,80,GET,/,HTTP/1.1,UA,,test-site.com,,,,*/*,,\"gzip, deflate\",,keep-alive,,HTTP/1.1,200,OK,25174,1\n",
        encoding="utf-8",
    )

    summary = convert_file(input_path=input_path, output_root=tmp_path / "data/raw", server_type="apache")
    outputs = summary["converted"][0]["output"]
    out_path = Path(outputs if isinstance(outputs, str) else outputs[0])
    lines = _read_lines(out_path)

    assert summary["counts"]["converted_files"] == 1
    assert summary["counts"]["raw_lines"] == 1
    assert '"GET / HTTP/1.1" 200 25174' in lines[0]


def test_convert_folder_and_skip_bad_file(tmp_path: Path):
    in_dir = tmp_path / "input"
    in_dir.mkdir()
    (in_dir / "ok.csv").write_text("timestamp,src_ip,request_http_method,request_http_request,response_http_status_code,response_content_length\n2020-01-01 00:00:00,1.1.1.1,GET,/a,200,12\n", encoding="utf-8")
    (in_dir / "bad.log").write_bytes(b"\xff\xfe\x00\x00")

    summary = convert_file(input_path=in_dir, output_root=tmp_path / "data/raw")

    assert summary["counts"]["converted_files"] >= 1
    assert summary["counts"]["raw_lines"] >= 1


def test_convert_split_large_output(tmp_path: Path, monkeypatch):
    from src.converter import convert_flow as flow

    monkeypatch.setattr(flow, "MAX_PART_BYTES", 120)

    input_path = tmp_path / "many.csv"
    input_path.write_text(
        "timestamp,src_ip,request_http_method,request_http_request,response_http_status_code,response_content_length\n"
        + "\n".join(
            f"2020-01-01 00:00:{i:02d},1.1.1.1,GET,/path-{i},200,12" for i in range(10)
        )
        + "\n",
        encoding="utf-8",
    )

    summary = convert_file(input_path=input_path, output_root=tmp_path / "data/raw", server_type="nginx")
    outputs = summary["converted"][0]["output"]

    assert isinstance(outputs, list)
    assert len(outputs) > 1
    assert all(Path(p).exists() for p in outputs)


def test_convert_http_request_block_to_single_access_line(tmp_path: Path):
    input_path = tmp_path / "request_block.log"
    input_path.write_text(
        "GET http://localhost:8080/tienda1/publico/anadir.jsp?id=2 HTTP/1.1\n"
        "User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux)\n"
        "Referer: http://localhost:8080/tienda1/publico/\n"
        "Host: localhost:8080\n"
        "Connection: close\n",
        encoding="utf-8",
    )

    summary = convert_file(input_path=input_path, output_root=tmp_path / "data/raw", server_type="apache")
    outputs = summary["converted"][0]["output"]
    out_path = Path(outputs if isinstance(outputs, str) else outputs[0])
    lines = _read_lines(out_path)

    assert len(lines) == 1
    assert '"GET http://localhost:8080/tienda1/publico/anadir.jsp?id=2 HTTP/1.1"' in lines[0]
    assert '"Mozilla/5.0 (compatible; Konqueror/3.5; Linux)"' in lines[0]
