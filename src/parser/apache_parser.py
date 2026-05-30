from __future__ import annotations

import re
from typing import Dict, Optional

from src.parser.base_parser import BaseParser


class ApacheParser(BaseParser):
    """
    Parser for Apache Common/Combined Log Format.

    Supports:
    - common
    - common_with_tail
    - combined
    - combined_with_tail

    The parser keeps raw request-target payloads intact but rejects control
    markers that can indicate log injection or bad continuation-line handling.
    """

    server_type = "apache"

    _BASE_PREFIX = (
        r"(?P<source_ip>\S+)\s+"
        r"\S+\s+\S+\s+"
        r"\[(?P<timestamp>[^\]]+)\]\s+"
    )

    _COMBINED_STRICT_PATTERN = (
        _BASE_PREFIX
        + r'"(?P<request>[^"]*)"\s+'
        + r"(?P<status_code>\S+)\s+"
        + r"(?P<response_size>\S+)\s+"
        + r'"(?P<referrer>[^"]*)"\s+'
        + r'"(?P<user_agent>[^"]*)"'
    )
    _COMMON_STRICT_PATTERN = (
        _BASE_PREFIX
        + r'"(?P<request>[^"]*)"\s+'
        + r"(?P<status_code>\S+)\s+"
        + r"(?P<response_size>\S+)"
    )

    # Greedy request parsing is used only after strict patterns so embedded
    # quotes in attack payloads can still be preserved when real logs contain
    # them.
    _COMBINED_PERMISSIVE_PATTERN = (
        _BASE_PREFIX
        + r'"(?P<request>.*)"\s+'
        + r"(?P<status_code>\S+)\s+"
        + r"(?P<response_size>\S+)\s+"
        + r'"(?P<referrer>[^"]*)"\s+'
        + r'"(?P<user_agent>[^"]*)"'
        + r"(?:\s+(?P<extra_tail>.+))?"
    )
    _COMMON_PERMISSIVE_PATTERN = (
        _BASE_PREFIX
        + r'"(?P<request>.*)"\s+'
        + r"(?P<status_code>\S+)\s+"
        + r"(?P<response_size>\S+)"
        + r"(?:\s+(?P<extra_tail>.+))?"
    )

    PROFILE_PATTERNS = (
        ("combined", re.compile(_COMBINED_STRICT_PATTERN)),
        ("combined_with_tail", re.compile(_COMBINED_STRICT_PATTERN + r"\s+(?P<extra_tail>.+)")),
        ("common", re.compile(_COMMON_STRICT_PATTERN)),
        ("common_with_tail", re.compile(_COMMON_STRICT_PATTERN + r"\s+(?P<extra_tail>.+)")),
        ("combined", re.compile(_COMBINED_PERMISSIVE_PATTERN)),
        ("common", re.compile(_COMMON_PERMISSIVE_PATTERN)),
    )

    def parse_line(self, line: str) -> Optional[Dict]:
        clean_line = line.strip()

        for profile, pattern in self.PROFILE_PATTERNS:
            match = pattern.fullmatch(clean_line)
            if not match:
                continue

            data = match.groupdict()
            data.setdefault("referrer", "-")
            data.setdefault("user_agent", "-")
            data["format_profile"] = profile

            extra_tail = data.get("extra_tail")
            if extra_tail is not None:
                data["extra_tail"] = extra_tail

            request = data.get("request", "")
            request_parts, request_error = self._parse_request_field(request)
            if request_error:
                return self._error_record(line=line, message=request_error)

            source_ip, ip_error = self._validate_source_ip(data.get("source_ip"))
            if ip_error:
                return self._error_record(line=line, message=ip_error)

            status_code, status_error = self._parse_status_code(data.get("status_code"))
            if status_error:
                return self._error_record(line=line, message=status_error)

            response_size, size_error = self._parse_response_size(data.get("response_size"))
            if size_error:
                return self._error_record(line=line, message=size_error)

            data.update(request_parts or {})
            data["source_ip"] = source_ip
            data["status_code"] = status_code
            data["response_size"] = response_size
            data["parse_error"] = False
            data.setdefault("error_message", None)

            return data

        return self._error_record(
            line=line,
            message=(
                "No Apache log pattern matched: supported profiles are "
                "combined/common with optional trailing custom fields"
            ),
        )
