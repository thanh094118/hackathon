from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlsplit


class Normalizer:
    """
    Module 3: Normalizer.

    Converts parsed Apache/Nginx/IIS records into one stable flat schema.
    The normalizer keeps raw/request-target values for forensic use while also
    producing validated and decoded fields for downstream analytics/detection.
    """

    SERVER_TYPE_VALUES = {"apache", "nginx", "iis"}
    HTTP_METHOD_VALUES = {
        "GET", "POST", "PUT", "DELETE", "PATCH",
        "HEAD", "OPTIONS", "CONNECT", "TRACE",
    }

    COMMON_FIELDS = [
        "event_id",
        "timestamp",
        "source_ip",
        "http_method",
        "original_url",
        "raw_uri",
        "uri",
        "query_string",
        "fragment",
        "status_code",
        "status_code_invalid",
        "response_size",
        "response_size_missing",
        "response_size_invalid",
        "user_agent",
        "referrer",
        "server_type",
        "raw_log",
        "line_number",
        "parse_status",
        "parse_error",
        "parse_error_message",
        "normalize_status",
        "normalize_errors",
        "error_message",
    ]

    def normalize(self, parsed_record: Dict[str, Any]) -> Dict[str, Any]:
        normalize_errors: list[str] = []

        parse_status = self._normalize_parse_status(parsed_record.get("parse_status"), normalize_errors)
        upstream_parse_error = bool(parsed_record.get("parse_error", False)) or parse_status == "error"
        parser_error_message = self._clean_text(parsed_record.get("error_message"))

        if upstream_parse_error and "parse_error" not in normalize_errors:
            normalize_errors.append("parse_error")

        server_type = self._normalize_server_type(parsed_record.get("server_type"), normalize_errors)
        timestamp = self._normalize_timestamp(parsed_record.get("timestamp"), server_type, normalize_errors)
        strict_field_validation = not upstream_parse_error
        source_ip = self._normalize_source_ip(parsed_record.get("source_ip"), normalize_errors, strict=strict_field_validation)
        http_method = self._normalize_http_method(parsed_record.get("http_method"), normalize_errors, strict=strict_field_validation)

        raw_uri = self._clean_text(parsed_record.get("raw_uri"))
        uri, query_string, fragment = self._split_uri(raw_uri)

        status_code, status_invalid = self._normalize_status_code(
            parsed_record.get("status_code"), strict=not upstream_parse_error
        )
        if status_invalid:
            normalize_errors.append("status_code_invalid")

        response_size, response_size_missing, response_size_invalid = self._normalize_response_size(
            parsed_record.get("response_size"), strict=not upstream_parse_error
        )
        if response_size_invalid:
            normalize_errors.append("response_size_invalid")

        original_url = self._clean_text(parsed_record.get("original_url")) or raw_uri
        parse_error = upstream_parse_error
        normalize_status = "error" if normalize_errors else "success"
        error_message = self._compose_error_message(parser_error_message, normalize_errors)

        values = {
            "event_id": parsed_record.get("event_id"),
            "timestamp": timestamp,
            "source_ip": source_ip,
            "http_method": http_method,
            "original_url": original_url,
            "raw_uri": raw_uri,
            "uri": uri,
            "query_string": query_string,
            "fragment": fragment,
            "status_code": status_code,
            "status_code_invalid": status_invalid,
            "response_size": response_size,
            "response_size_missing": response_size_missing,
            "response_size_invalid": response_size_invalid,
            "user_agent": self._clean_empty(parsed_record.get("user_agent")),
            "referrer": self._clean_empty(parsed_record.get("referrer")),
            "server_type": server_type,
            "raw_log": parsed_record.get("raw_log"),
            "line_number": parsed_record.get("line_number"),
            "parse_status": parse_status,
            "parse_error": parse_error,
            "parse_error_message": parser_error_message,
            "normalize_status": normalize_status,
            "normalize_errors": normalize_errors,
            "error_message": error_message,
        }
        return {field: values.get(field) for field in self.COMMON_FIELDS}

    @classmethod
    def _split_uri(cls, raw_uri: Optional[str]) -> tuple[Optional[str], Optional[str], Optional[str]]:
        if not raw_uri:
            return None, None, None

        try:
            split_result = urlsplit(raw_uri)
            uri = split_result.path or raw_uri.split("#", 1)[0].split("?", 1)[0] or None
            
            if split_result.query:
                query_string = split_result.query
            else:
                pre_fragment = raw_uri.split("#", 1)[0]
                query_string = pre_fragment.split("?", 1)[1] if "?" in pre_fragment else ""

            fragment = split_result.fragment or None
            return uri, query_string, fragment
        except Exception:
            # Fallback for truly malformed URLs
            uri = raw_uri.split("#", 1)[0].split("?", 1)[0]
            query_string = ""
            if "?" in raw_uri:
                query_string = raw_uri.split("?", 1)[1].split("#", 1)[0]
            fragment = None
            if "#" in raw_uri:
                fragment = raw_uri.split("#", 1)[1]
            return uri, query_string, fragment

    def _normalize_timestamp(
        self,
        value: Any,
        server_type: Optional[str],
        normalize_errors: list[str],
    ) -> Optional[str]:
        text = self._clean_text(value)
        if not text:
            return None

        dt: Optional[datetime] = None
        if server_type in {"apache", "nginx"}:
            dt = self._parse_with_formats(text, ("%d/%b/%Y:%H:%M:%S %z",))
        elif server_type == "iis":
            dt = self._parse_with_formats(text, ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"))
            if dt is not None and dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        else:
            # Try ISO formats
            dt = self._parse_iso8601(text)

        if dt is None:
            normalize_errors.append("timestamp_invalid")
            return None
        return dt.isoformat()

    @staticmethod
    def _parse_with_formats(value: str, formats: tuple[str, ...]) -> Optional[datetime]:
        for fmt in formats:
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
        return None

    @staticmethod
    def _parse_iso8601(value: str) -> Optional[datetime]:
        candidate = value.strip()
        if candidate.endswith("Z"):
            candidate = candidate[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(candidate)
        except ValueError:
            return None

    def _normalize_source_ip(self, value: Any, normalize_errors: list[str], *, strict: bool) -> Optional[str]:
        text = self._clean_text(value)
        if not text:
            if strict:
                normalize_errors.append("source_ip_invalid")
            return None
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            normalize_errors.append("source_ip_invalid")
            return None

    def _normalize_http_method(self, value: Any, normalize_errors: list[str], *, strict: bool) -> Optional[str]:
        method = (self._clean_text(value) or "").upper()
        if not method:
            if strict:
                normalize_errors.append("http_method_invalid")
            return None
        if method not in self.HTTP_METHOD_VALUES:
            normalize_errors.append("http_method_invalid")
            return None
        return method

    def _normalize_server_type(self, value: Any, normalize_errors: list[str]) -> Optional[str]:
        text = (self._clean_text(value) or "").lower()
        if not text:
            normalize_errors.append("server_type_invalid")
            return None
        if text not in self.SERVER_TYPE_VALUES:
            normalize_errors.append("server_type_invalid")
            return None
        return text

    @staticmethod
    def _normalize_status_code(value: Any, *, strict: bool) -> tuple[int, bool]:
        text = Normalizer._clean_text(value)
        if not text:
            return 0, strict
        try:
            status_code = int(text)
        except (TypeError, ValueError):
            return 0, strict
        if strict and not (100 <= status_code <= 599):
            return 0, True
        return status_code, False

    @staticmethod
    def _normalize_response_size(value: Any, *, strict: bool) -> tuple[int, bool, bool]:
        text = Normalizer._clean_text(value)
        if not text:
            return 0, True, False
        try:
            response_size = int(text)
        except (TypeError, ValueError):
            return 0, False, strict
        if strict and response_size < 0:
            return 0, False, True
        return response_size, False, False

    @staticmethod
    def _normalize_parse_status(value: Any, normalize_errors: list[str]) -> str:
        text = str(value or "").strip().lower()
        if text in {"success", "error"}:
            return text
        if not text:
            normalize_errors.append("parse_status_missing")
        else:
            normalize_errors.append("parse_status_invalid")
        return "error"

    @staticmethod
    def _compose_error_message(parser_error_message: Optional[str], normalize_errors: list[str]) -> Optional[str]:
        if parser_error_message:
            return parser_error_message
        if normalize_errors:
            return f"normalize_errors={','.join(normalize_errors)}"
        return None

    @staticmethod
    def _clean_empty(value: Any) -> Optional[str]:
        return Normalizer._clean_text(value)

    @staticmethod
    def _clean_text(value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        if not text or text == "-":
            return None
        return text
