from __future__ import annotations

from abc import ABC, abstractmethod
import hashlib
import ipaddress
import re
from typing import Dict, Iterable, Iterator, Optional, Tuple


class BaseParser(ABC):
    """
    Module 2: Base Parser.

    A parser converts raw access-log lines into structured records.
    The base class owns the shared streaming flow, event_id generation,
    common error schema, and low-level validation helpers.
    """

    server_type: str = "unknown"

    VALID_HTTP_METHODS = {
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
        "CONNECT",
        "TRACE",
    }

    REQUEST_PATTERN = re.compile(
        r"(?P<http_method>\S+)\s+(?P<raw_uri>.+?)\s+(?P<http_version>HTTP/\d(?:\.\d)?)"
    )
    REQUEST_NO_VERSION_PATTERN = re.compile(
        r"(?P<http_method>\S+)\s+(?P<raw_uri>\S.*)"
    )
    _HTTP_VERSION_TOKEN_PATTERN = re.compile(r"HTTP/\d(?:\.\d)?")
    _REQUEST_FORBIDDEN_MARKERS = ("\n", "\r", "\t", "\\n", "\\r", "\\t")

    _ERROR_RECORD_DEFAULTS = {
        "timestamp": None,
        "source_ip": None,
        "request": None,
        "http_method": None,
        "raw_uri": None,
        "original_url": None,
        "http_version": None,
        "status_code": None,
        "response_size": None,
        "referrer": None,
        "user_agent": None,
        "format_profile": None,
        "extra_tail": None,
        "data_line_number": None,
    }

    def __init__(self) -> None:
        self._event_namespace: Optional[str] = None
        self._resolved_server_type: Optional[str] = None

    @abstractmethod
    def parse_line(self, line: str) -> Optional[Dict]:
        """Parse one physical log line. Return None for ignorable lines."""
        raise NotImplementedError

    def parse_lines(self, lines: Iterable[str]) -> Iterator[Dict]:
        """
        Stream parsed records.

        Returning an iterator avoids loading large log files into RAM.
        Use list(parser.parse_lines(lines)) at the call site if a list is needed.
        """
        yield from self.iter_lines(lines)

    def iter_lines(self, lines: Iterable[str]) -> Iterator[Dict]:
        effective_server_type = self._effective_server_type()

        for line_number, line in enumerate(lines, start=1):
            parsed = self.parse_line(line)
            if parsed is None:
                continue

            parsed.setdefault("parse_error", False)
            parsed.setdefault("error_message", None)
            parsed["parse_status"] = "error" if parsed.get("parse_error") else "success"
            parsed["line_number"] = line_number
            parsed["server_type"] = effective_server_type
            parsed.setdefault("raw_log", line)

            if parsed.get("raw_uri") is not None:
                parsed.setdefault("original_url", parsed.get("raw_uri"))
            else:
                parsed.setdefault("original_url", None)

            parsed.setdefault(
                "event_id",
                self._build_event_id(
                    line_number=line_number,
                    raw_log=str(parsed.get("raw_log", "")),
                ),
            )

            # Keep a predictable minimum schema for both success and error records.
            for key, value in self._ERROR_RECORD_DEFAULTS.items():
                parsed.setdefault(key, value)

            yield parsed

    def set_event_namespace(self, namespace: Optional[str]) -> None:
        """
        Add a source namespace to event_id, for example a source-file hash.

        This prevents event_id collisions when multiple files contain the same
        line_number and identical raw_log content.
        """
        self._event_namespace = namespace

    def set_resolved_server_type(self, server_type: Optional[str]) -> None:
        self._resolved_server_type = server_type.strip().lower() if server_type else None

    def _effective_server_type(self) -> str:
        return self._resolved_server_type or self.server_type

    def _build_event_id(self, *, line_number: int, raw_log: str) -> str:
        digest = hashlib.sha1(
            str(raw_log).encode("utf-8", errors="ignore")
        ).hexdigest()[:12]
        effective_server_type = self._effective_server_type()

        if self._event_namespace:
            return f"{effective_server_type}:{line_number}:{self._event_namespace}:{digest}"
        return f"{effective_server_type}:{line_number}:{digest}"

    def _error_record(self, *, line: str, message: str, **overrides) -> Dict:
        record = dict(self._ERROR_RECORD_DEFAULTS)
        record.update(
            {
                "parse_error": True,
                "error_message": message,
                "raw_log": line,
            }
        )
        record.update(overrides)
        return record

    def _parse_request_field(self, request: str) -> Tuple[Optional[Dict[str, Optional[str]]], Optional[str]]:
        request_text = str(request or "")

        if self._contains_forbidden_request_marker(request_text):
            return None, "Request field contains forbidden control marker"

        match = self.REQUEST_PATTERN.fullmatch(request_text)
        if match:
            data = match.groupdict()
        else:
            # If an HTTP version token exists but the full pattern failed, the
            # request field is malformed rather than a no-version request.
            if self._HTTP_VERSION_TOKEN_PATTERN.search(request_text):
                return None, "Request field does not match expected format"

            match_no_version = self.REQUEST_NO_VERSION_PATTERN.fullmatch(request_text)
            if not match_no_version:
                return None, "Request field does not match expected format"

            data = match_no_version.groupdict()
            data["http_version"] = None

        method = str(data.get("http_method") or "").upper()
        if method not in self.VALID_HTTP_METHODS:
            return None, "Invalid http_method in request field"

        data["http_method"] = method
        return data, None

    @classmethod
    def _contains_forbidden_request_marker(cls, request: str) -> bool:
        return any(marker in request for marker in cls._REQUEST_FORBIDDEN_MARKERS)

    @staticmethod
    def _validate_source_ip(value: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
        if value is None:
            return None, "Invalid source_ip"

        text = str(value).strip()
        try:
            return str(ipaddress.ip_address(text)), None
        except ValueError:
            return None, "Invalid source_ip"

    @staticmethod
    def _parse_status_code(value) -> Tuple[Optional[int], Optional[str]]:
        try:
            status = int(value)
        except (TypeError, ValueError):
            return None, "Invalid status_code"

        if not 100 <= status <= 599:
            return None, "Invalid status_code"
        return status, None

    @staticmethod
    def _parse_response_size(value) -> Tuple[Optional[int], Optional[str]]:
        if value == "-":
            return 0, None

        try:
            size = int(value)
        except (TypeError, ValueError):
            return None, "Invalid response_size"

        if size < 0:
            return None, "Invalid response_size"
        return size, None
