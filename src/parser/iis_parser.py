from __future__ import annotations

import shlex
from typing import Dict, Iterable, Iterator, List, Optional

from src.parser.base_parser import BaseParser


class IISParser(BaseParser):
    """
    Parser for IIS W3C Extended Log Format.

    IIS logs use a #Fields line to define the column order. This parser keeps
    field state per parse_lines() call and resets it before every new stream,
    so the same parser instance can be reused safely for multiple files.
    """

    server_type = "iis"

    def __init__(self) -> None:
        super().__init__()
        self.fields: List[str] = []

    def reset(self) -> None:
        self.fields = []

    def parse_line(self, line: str) -> Optional[Dict]:
        stripped = line.strip()

        if not stripped:
            return None

        if stripped.startswith("#Fields:"):
            self.fields = stripped.replace("#Fields:", "", 1).strip().split()
            return None

        if stripped.startswith("#"):
            return None

        if not self.fields:
            return self._error_record(
                line=line,
                message="Missing #Fields header before IIS data line",
            )

        parts, split_error = self._split_fields(stripped)
        if split_error:
            return self._error_record(
                line=line,
                message=split_error,
            )

        if len(parts) != len(self.fields):
            return self._error_record(
                line=line,
                message=f"IIS field count mismatch: expected {len(self.fields)}, got {len(parts)}",
            )

        row = dict(zip(self.fields, parts))

        date = row.get("date")
        time = row.get("time")
        timestamp = f"{date} {time}" if date and time else None

        raw_uri = row.get("cs-uri-stem")
        query = row.get("cs-uri-query")
        if raw_uri and query and query != "-":
            raw_uri = f"{raw_uri}?{query}"

        source_ip, ip_error = self._validate_source_ip(row.get("c-ip"))
        if ip_error:
            return self._error_record(line=line, message=ip_error)

        method = row.get("cs-method")
        if method is None or method.upper() not in self.VALID_HTTP_METHODS:
            return self._error_record(line=line, message="Invalid http_method in request field")

        status_code, status_error = self._parse_status_code(row.get("sc-status"))
        if status_error:
            return self._error_record(line=line, message=status_error)

        response_size, size_error = self._parse_response_size(row.get("sc-bytes", "0"))
        if size_error:
            return self._error_record(line=line, message=size_error)

        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "request": None,
            "http_method": method.upper(),
            "raw_uri": raw_uri,
            "original_url": raw_uri,
            "http_version": None,
            "status_code": status_code,
            "response_size": response_size,
            "referrer": row.get("cs(Referer)", "-"),
            "user_agent": row.get("cs(User-Agent)", "-"),
            "format_profile": "w3c",
            "extra_tail": None,
            "parse_error": False,
            "error_message": None,
        }

    def parse_lines(self, lines: Iterable[str]) -> Iterator[Dict]:
        """
        Stream IIS records and add data_line_number.

        This method still delegates the shared parse flow to BaseParser via
        super().parse_lines(...), avoiding duplicated event_id/schema logic.
        """
        self.reset()
        data_line_number = 0

        for parsed in super().parse_lines(lines):
            if parsed.get("parse_status") == "success":
                data_line_number += 1
                parsed["data_line_number"] = data_line_number
            else:
                parsed["data_line_number"] = None
            yield parsed

    @staticmethod
    def _split_fields(line: str) -> tuple[Optional[List[str]], Optional[str]]:
        try:
            return shlex.split(line), None
        except ValueError as exc:
            return None, f"Malformed quoted IIS fields: {exc}"
