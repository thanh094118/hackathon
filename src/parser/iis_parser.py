from typing import Dict, Iterable, List, Optional

from src.parser.base_parser import BaseParser


class IISParser(BaseParser):
    """
    Parser for IIS W3C Extended Log Format.

    IIS logs often contain a #Fields line that defines column order.
    Example:
    #Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status sc-bytes cs(User-Agent) cs(Referer)
    """

    server_type = "iis"

    def __init__(self):
        self.fields: List[str] = []

    def parse_line(self, line: str) -> Optional[Dict]:
        stripped = line.strip()

        if not stripped:
            return None

        if stripped.startswith("#Fields:"):
            self.fields = stripped.replace("#Fields:", "").strip().split()
            return None

        if stripped.startswith("#"):
            return None

        if not self.fields:
            return {
                "parse_error": True,
                "error_message": "Missing #Fields header before IIS data line",
                "raw_log": line,
                "server_type": self.server_type,
            }

        parts = stripped.split()

        if len(parts) != len(self.fields):
            return {
                "parse_error": True,
                "error_message": f"IIS field count mismatch: expected {len(self.fields)}, got {len(parts)}",
                "raw_log": line,
                "server_type": self.server_type,
            }

        row = dict(zip(self.fields, parts))

        date = row.get("date")
        time = row.get("time")
        timestamp = f"{date} {time}" if date and time else None

        raw_uri = row.get("cs-uri-stem", "")
        query = row.get("cs-uri-query", "-")
        if query and query != "-":
            raw_uri = f"{raw_uri}?{query}"

        status = row.get("sc-status", "0")
        response_size = row.get("sc-bytes", "0")

        return {
            "timestamp": timestamp,
            "source_ip": row.get("c-ip"),
            "http_method": row.get("cs-method"),
            "raw_uri": raw_uri,
            "http_version": None,
            "status_code": self._to_int(status),
            "response_size": self._to_int(response_size),
            "referrer": row.get("cs(Referer)", "-"),
            "user_agent": row.get("cs(User-Agent)", "-"),
            "parse_error": False,
        }

    def parse_lines(self, lines: Iterable[str]) -> List[Dict]:
        records = []
        data_line_number = 0

        for physical_line_number, line in enumerate(lines, start=1):
            parsed = self.parse_line(line)

            if parsed is None:
                continue

            data_line_number += 1
            parsed["line_number"] = physical_line_number
            parsed["data_line_number"] = data_line_number
            parsed["server_type"] = self.server_type
            parsed["raw_log"] = line
            records.append(parsed)

        return records

    @staticmethod
    def _to_int(value: str) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0
