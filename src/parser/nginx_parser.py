import re
from typing import Dict, Optional

from src.parser.apache_parser import ApacheParser


class NginxParser(ApacheParser):
    """
    Parser for Nginx access logs.

    Supported profiles:
    - combined: default Nginx/Apache combined format
    - combined_with_tail: combined format plus trailing custom fields
      appended after user-agent
    """

    server_type = "nginx"

    _COMBINED_CORE_PATTERN = (
        r'(?P<source_ip>\S+)\s+'
        r'\S+\s+\S+\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+'
        r'(?P<status_code>\d{3})\s+'
        r'(?P<response_size>\S+)\s+'
        r'"(?P<referrer>[^"]*)"\s+'
        r'"(?P<user_agent>[^"]*)"'
    )
    _COMMON_CORE_PATTERN = (
        r'(?P<source_ip>\S+)\s+'
        r'\S+\s+\S+\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+'
        r'(?P<status_code>\d{3})\s+'
        r'(?P<response_size>\S+)'
    )

    PROFILE_PATTERNS = (
        re.compile(_COMBINED_CORE_PATTERN),
        re.compile(_COMBINED_CORE_PATTERN + r"\s+(?P<extra_tail>.+)"),
        re.compile(_COMMON_CORE_PATTERN),
        re.compile(_COMMON_CORE_PATTERN + r"\s+(?P<extra_tail>.+)"),
    )

    def parse_line(self, line: str) -> Optional[Dict]:
        clean_line = line.strip()
        for pattern in self.PROFILE_PATTERNS:
            match = pattern.fullmatch(clean_line)
            if not match:
                continue

            data = match.groupdict()
            data.pop("extra_tail", None)
            data.setdefault("referrer", "-")
            data.setdefault("user_agent", "-")

            request = data.get("request", "")
            request_match = self.REQUEST_PATTERN.fullmatch(request)
            if request_match:
                data.update(request_match.groupdict())
            else:
                data.update({
                    "http_method": None,
                    "raw_uri": None,
                    "http_version": None,
                    "parse_error": True,
                    "error_message": "Request field does not match expected format",
                })

            data["status_code"] = int(data["status_code"])
            data["response_size"] = self._parse_response_size(data["response_size"])
            data["original_url"] = data.get("raw_uri")
            data.setdefault("parse_error", False)
            return data

        return {
            "parse_error": True,
            "error_message": (
                "Line does not match supported Nginx log profiles "
                "(combined or combined with trailing custom fields)"
            ),
            "request": None,
            "raw_uri": None,
            "http_method": None,
            "http_version": None,
            "status_code": 0,
            "response_size": 0,
            "referrer": None,
            "user_agent": None,
            "raw_log": line,
            "server_type": self.server_type,
        }
