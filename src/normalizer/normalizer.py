from datetime import datetime, timezone
from typing import Dict, Optional
from urllib.parse import urlsplit

from dateutil import parser as date_parser


class Normalizer:
    """
    Module 3: Normalizer.

    Converts parsed records from Apache/Nginx/IIS into one common schema.
    """

    COMMON_FIELDS = [
        "timestamp",
        "source_ip",
        "http_method",
        "original_url",
        "uri",
        "query_string",
        "status_code",
        "response_size",
        "user_agent",
        "referrer",
        "server_type",
        "raw_log",
        "line_number",
        "parse_status",
        "normalize_status",
        "parse_error",
        "error_message",
    ]

    def normalize(self, parsed_record: Dict) -> Dict:
        raw_uri = parsed_record.get("raw_uri") or ""
        uri, query_string = self._split_uri(raw_uri)

        normalized = {
            "timestamp": self._normalize_timestamp(
                parsed_record.get("timestamp"),
                parsed_record.get("server_type")
            ),
            "source_ip": parsed_record.get("source_ip"),
            "http_method": self._upper_or_none(parsed_record.get("http_method")),
            "original_url": parsed_record.get("original_url") or raw_uri,
            "uri": uri,
            "query_string": query_string,
            "status_code": self._to_int(parsed_record.get("status_code")),
            "response_size": self._to_int(parsed_record.get("response_size")),
            "user_agent": self._clean_empty(parsed_record.get("user_agent")),
            "referrer": self._clean_empty(parsed_record.get("referrer")),
            "server_type": parsed_record.get("server_type"),
            "raw_log": parsed_record.get("raw_log"),
            "line_number": parsed_record.get("line_number"),
            "parse_status": parsed_record.get("parse_status", "success"),
            "normalize_status": "error" if bool(parsed_record.get("parse_error", False)) else "success",
            "parse_error": bool(parsed_record.get("parse_error", False)),
            "error_message": parsed_record.get("error_message"),
            "event_id": parsed_record.get("event_id"),
        }

        return normalized

    @staticmethod
    def _split_uri(raw_uri: str) -> tuple[str, str]:
        if not raw_uri:
            return "", ""

        split_result = urlsplit(raw_uri)
        uri = split_result.path or raw_uri.split("?", 1)[0]

        if split_result.query:
            query_string = split_result.query
        elif "?" in raw_uri:
            query_string = raw_uri.split("?", 1)[1]
        else:
            query_string = ""

        return uri, query_string

    @staticmethod
    def _normalize_timestamp(value: Optional[str], server_type: Optional[str]) -> Optional[str]:
        if not value:
            return None

        try:
            if server_type in {"apache", "nginx"}:
                dt = datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
                return dt.isoformat()

            if server_type == "iis":
                dt = date_parser.parse(value)
                # IIS W3C logs are usually UTC by convention.
                # For MVP, mark as UTC if timezone is absent.
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.isoformat()

            dt = date_parser.parse(value)
            return dt.isoformat()

        except Exception:
            return value

    @staticmethod
    def _upper_or_none(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return str(value).upper()

    @staticmethod
    def _to_int(value) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _clean_empty(value) -> str:
        if value is None:
            return ""
        if value == "-":
            return ""
        return str(value)
