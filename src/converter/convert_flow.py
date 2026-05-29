from __future__ import annotations

import argparse
import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional

SERVER_TYPE_CHOICES = ("apache", "nginx", "iis")
_REQUEST_LINE_PATTERN = re.compile(r"^(?P<method>[A-Z]{2,16})\s+(?P<target>\S.*?)(?:\s+(?P<version>HTTP/\d(?:\.\d)?))?$")
_START_BLOCK_PATTERN = re.compile(r"^Start\s*-\s*Id\s*:\s*.+$", re.IGNORECASE)
_END_BLOCK_PATTERN = re.compile(r"^End\s*-\s*Id\s*:\s*.+$", re.IGNORECASE)

MAX_PART_BYTES = 50 * 1024 * 1024

_URI_KEYS = ("raw_uri", "original_url", "uri", "url", "uri_path", "path", "request_uri", "cs_uri_stem", "request_http_request")
_QUERY_KEYS = ("query_string", "query", "cs_uri_query")
_METHOD_KEYS = ("http_method", "method", "verb", "cs_method", "request_http_method")
_STATUS_KEYS = ("status_code", "status", "http_status", "response_status", "sc_status", "response_http_status_code")
_SIZE_KEYS = ("response_size", "bytes", "size", "content_length", "response_content_length", "sc_bytes")
_SOURCE_IP_KEYS = ("source_ip", "ip", "client_ip", "remote_addr", "c_ip", "src_ip")
_UA_KEYS = ("user_agent", "ua", "cs_user_agent", "request_user_agent")
_REFERRER_KEYS = ("referrer", "referer", "cs_referer", "request_referer")
_HTTP_VERSION_KEYS = ("http_version", "protocol", "request_protocol", "request_http_protocol")
_TIMESTAMP_KEYS = ("timestamp", "time", "date_time", "datetime", "@timestamp")


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert heterogeneous inputs (.txt/.log/.csv/.json/.jsonl) to raw access.log lines"
    )
    parser.add_argument("--input", required=True, help="Input file or folder path")
    parser.add_argument("--output-root", default="data/raw", help="Output root directory for .log files (default: data/raw)")
    parser.add_argument("--server-type", choices=SERVER_TYPE_CHOICES, default=None, help="Optional server_type override")
    return parser


def main() -> None:
    args = build_cli().parse_args()
    summary = convert_file(input_path=args.input, output_root=args.output_root, server_type=args.server_type)

    print("[+] Conversion finished")
    print(f"[+] Input: {summary['input_path']}")
    print(f"[+] Converted files: {summary['counts']['converted_files']}")
    print(f"[+] Skipped files: {summary['counts']['skipped_files']}")
    print(f"[+] Raw lines: {summary['counts']['raw_lines']}")


def convert_file(*, input_path: str | Path, output_root: str | Path = "data/raw", server_type: Optional[str] = None) -> Dict[str, Any]:
    source_path = Path(input_path)
    if not source_path.exists():
        raise FileNotFoundError(f"Input path not found: {source_path}")

    files = _collect_input_files(source_path)
    converted: List[Dict[str, Any]] = []
    skipped: List[Dict[str, str]] = []

    for path in files:
        try:
            summary = _convert_single_file(path=path, output_root=Path(output_root), server_type=server_type)
            converted.append(summary)
        except Exception as exc:
            skipped.append({"input": str(path), "reason": str(exc)})

    return {
        "input_path": str(source_path),
        "counts": {
            "converted_files": len(converted),
            "skipped_files": len(skipped),
            "raw_lines": sum(int(item["counts"]["raw_lines"]) for item in converted),
        },
        "converted": converted,
        "skipped": skipped,
        "output": converted[0]["output"] if len(converted) == 1 else None,
        "server_type": server_type.lower() if server_type else None,
    }


def _collect_input_files(path: Path) -> List[Path]:
    if path.is_file():
        return [path]
    if path.is_dir():
        out: List[Path] = []
        for item in sorted(path.rglob("*")):
            if item.is_file() and item.suffix.lower() in {".txt", ".log", ".csv", ".json", ".jsonl"}:
                out.append(item)
        return out
    raise ValueError(f"Input path is not file/folder: {path}")


def _convert_single_file(*, path: Path, output_root: Path, server_type: Optional[str]) -> Dict[str, Any]:
    resolved_server_type = (server_type or _detect_server_type_from_path(path) or "apache").lower()
    output_dir = output_root / resolved_server_type
    output_dir.mkdir(parents=True, exist_ok=True)

    items = list(_iter_input_items(path))
    lines: List[str] = []
    for item in items:
        for line in _to_raw_log_lines(item):
            if line.strip():
                lines.append(line.strip())

    parts = _chunk_lines_by_bytes(lines, MAX_PART_BYTES)
    outputs: List[str] = []
    for idx, chunk in enumerate(parts, start=1):
        suffix = "" if len(parts) == 1 else f"_part{idx:03d}"
        out = output_dir / f"converted_{path.stem}{suffix}.log"
        out.write_text("\n".join(chunk) + ("\n" if chunk else ""), encoding="utf-8")
        outputs.append(str(out))

    return {
        "input_path": str(path),
        "server_type": resolved_server_type,
        "counts": {"raw_lines": len(lines), "parts": len(parts)},
        "output": outputs[0] if len(outputs) == 1 else outputs,
    }


def _chunk_lines_by_bytes(lines: List[str], max_bytes: int) -> List[List[str]]:
    if not lines:
        return [[]]
    parts: List[List[str]] = []
    current: List[str] = []
    current_bytes = 0
    for line in lines:
        lb = len((line + "\n").encode("utf-8"))
        if current and current_bytes + lb > max_bytes:
            parts.append(current)
            current = []
            current_bytes = 0
        current.append(line)
        current_bytes += lb
    if current:
        parts.append(current)
    return parts

# keep existing helper logic

def _iter_input_items(path: Path) -> Iterator[Any]:
    suffix = path.suffix.lower()
    if suffix in {".txt", ".log"}:
        yield from _iter_text_entries(path)
        return
    if suffix == ".csv":
        yield from _iter_csv_rows(path)
        return
    if suffix in {".json", ".jsonl"}:
        yield from _iter_json_rows(path)
        return
    raise ValueError(f"Unsupported input extension: {suffix}")


def _iter_text_entries(path: Path) -> Iterator[str]:
    with path.open("rb") as handle:
        for raw_line in handle:
            line = raw_line.decode("utf-8", errors="ignore").rstrip("\r\n")
            if line.strip():
                yield line


def _iter_csv_rows(path: Path) -> Iterator[Dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            yield {str(k): v for k, v in row.items()}


def _iter_json_rows(path: Path) -> Iterator[Any]:
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                text = line.strip()
                if text:
                    yield json.loads(text)
        return
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        yield from data
    else:
        yield data


def _to_raw_log_lines(item: Any) -> List[str]:
    if isinstance(item, str):
        return [item]
    if isinstance(item, Mapping):
        return [_from_mapping_item(item)]
    return [str(item)]


def _from_mapping_item(item: Mapping[str, Any]) -> str:
    normalized = _normalize_keys(item)
    uri = _pick_text(normalized, *_URI_KEYS) or "/"
    method = _pick_text(normalized, *_METHOD_KEYS) or "GET"
    return _build_access_log_line({
        "source_ip": _pick_text(normalized, *_SOURCE_IP_KEYS) or "0.0.0.0",
        "timestamp": _pick_text(normalized, *_TIMESTAMP_KEYS),
        "http_method": method,
        "raw_uri": uri,
        "http_version": _pick_text(normalized, *_HTTP_VERSION_KEYS) or "HTTP/1.1",
        "status_code": _pick_int(normalized, *_STATUS_KEYS, default=200),
        "response_size": _pick_int(normalized, *_SIZE_KEYS, default=0),
        "referrer": _pick_text(normalized, *_REFERRER_KEYS) or "-",
        "user_agent": _pick_text(normalized, *_UA_KEYS) or "-",
    })


def _build_access_log_line(payload: Mapping[str, Any]) -> str:
    source_ip = str(payload.get("source_ip") or "0.0.0.0").strip() or "0.0.0.0"
    timestamp = _to_apache_timestamp(payload.get("timestamp"))
    method = str(payload.get("http_method") or "GET").strip().upper() or "GET"
    raw_uri = str(payload.get("raw_uri") or "/").strip() or "/"
    http_version = str(payload.get("http_version") or "HTTP/1.1").strip() or "HTTP/1.1"
    status_code = _to_int(payload.get("status_code"), default=200)
    response_size = _to_int(payload.get("response_size"), default=0)
    referrer = _escape_quoted(str(payload.get("referrer") or "-"))
    user_agent = _escape_quoted(str(payload.get("user_agent") or "-"))
    request = _escape_quoted(f"{method} {raw_uri} {http_version}".strip())
    return f'{source_ip} - - [{timestamp}] "{request}" {status_code} {response_size} "{referrer}" "{user_agent}"'


def _to_apache_timestamp(value: Any) -> str:
    text = str(value or "").strip()
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(text, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.strftime("%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            continue
    return datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S %z")


def _escape_quoted(value: str) -> str:
    return value.replace('"', '\\"')


def _detect_server_type_from_path(input_path: Path) -> Optional[str]:
    for segment in input_path.parts:
        name = str(segment).strip().lower()
        if name in SERVER_TYPE_CHOICES:
            return name
    return None


def _normalize_keys(record: Mapping[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in record.items():
        text = str(key).strip().strip('"').strip("'").lower()
        text = text.replace("-", "_").replace(" ", "_")
        out[text] = value
    return out


def _pick_value(record: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in record and record[key] not in (None, ""):
            return record[key]
    return None


def _pick_text(record: Mapping[str, Any], *keys: str) -> str:
    value = _pick_value(record, *keys)
    return "" if value is None else str(value).strip()


def _pick_int(record: Mapping[str, Any], *keys: str, default: int) -> int:
    return _to_int(_pick_value(record, *keys), default=default)


def _to_int(value: Any, *, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
