import re
from typing import Dict, Optional

from src.parser.base_parser import BaseParser


class ApacheParser(BaseParser):
    """
    Parser for Apache combined log format.

    Example:
    192.168.1.10 - - [18/May/2026:10:15:30 +0700]
    "GET /search.php?q=test HTTP/1.1" 200 5321 "-" "Mozilla/5.0"
    """

    server_type = "apache"

    COMBINED_LOG_PATTERN = re.compile(
        r'(?P<source_ip>\S+)\s+'
        r'\S+\s+\S+\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+'
        r'(?P<status_code>\d{3})\s+'
        r'(?P<response_size>\S+)\s+'
        r'"(?P<referrer>[^"]*)"\s+'
        r'"(?P<user_agent>[^"]*)"'
    )
    COMMON_LOG_PATTERN = re.compile(
        r'(?P<source_ip>\S+)\s+'
        r'\S+\s+\S+\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+'
        r'(?P<status_code>\d{3})\s+'
        r'(?P<response_size>\S+)'
    )

    REQUEST_PATTERN = re.compile(
        r'(?P<http_method>[A-Z]+)\s+(?P<raw_uri>\S+)\s+(?P<http_version>HTTP/\d(?:\.\d)?)'
    )

    def parse_line(self, line: str) -> Optional[Dict]:
        clean_line = line.strip()
        match = self.COMBINED_LOG_PATTERN.fullmatch(clean_line)
        if not match:
            match = self.COMMON_LOG_PATTERN.fullmatch(clean_line)
        if not match:
            return {
                "parse_error": True,
                "error_message": "Line does not match Apache combined log format",
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

        data = match.groupdict()
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

    @staticmethod
    def _parse_response_size(value: str) -> int:
        if value == "-":
            return 0
        try:
            return int(value)
        except ValueError:
            return 0
