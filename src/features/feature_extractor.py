from __future__ import annotations

import math
import re
from typing import Any, Dict, Iterable, List, Mapping
from urllib.parse import parse_qsl


class FeatureExtractor:
    """
    Module 6: Feature Extractor.

    Converts a normalized/preprocessed request into hand-crafted numeric features.

    Design:
    - Input is expected from RequestPreprocessor.
    - Features are computed per field where possible to avoid mixing URI/query/UA signals.
    - Output schema is fixed via FEATURE_NAMES for train/inference consistency.
    - enrich() prefixes features with feature_ and preserves original record fields.
    """

    FEATURE_VERSION = "handcrafted_v2"

    SQL_KEYWORDS = [
        "select", "union", "insert", "update", "delete", "drop",
        "information_schema", "sleep(", "benchmark(", "or 1=1", "and 1=1",
    ]

    XSS_KEYWORDS = [
        "<script", "<svg", "<img", "onerror=", "onload=", "javascript:",
        "document.cookie", "srcdoc=", "ontoggle=",
    ]

    TRAVERSAL_KEYWORDS = [
        "../", "..\\", "/etc/passwd", "win.ini", "boot.ini",
    ]

    # Keep scanner list here only as a numeric ML feature. RuleDetector remains
    # responsible for explainable scanner rule IDs.
    SCANNER_USER_AGENTS = [
        "sqlmap", "nikto", "acunetix", "nessus", "openvas",
        "nmap", "gobuster", "ffuf", "dirbuster",
    ]

    SPECIAL_CHARS = set("'\"<>;(){}[]../\\=%-&|")
    SQLI_EVASION_PATTERN = re.compile(
        r"(?:'|\b)(?:\s|/\*.*?\*/|%0a|%0d|%09)*(?:or|and)(?:\s|/\*.*?\*/|%0a|%0d|%09)+\d+\s*=\s*\d+",
        flags=re.IGNORECASE,
    )
    UNION_SELECT_PATTERN = re.compile(r"\bunion(?:\s|/\*.*?\*/)+select\b", flags=re.IGNORECASE)

    FEATURE_NAMES = [
        # Length features
        "uri_length",
        "query_length",
        "request_length",
        "user_agent_length",

        # Query structure
        "param_count",
        "param_name_count",
        "avg_param_name_length",
        "avg_param_value_length",

        # Aggregate request counts kept for backward compatibility
        "special_char_count",
        "digit_count",
        "alpha_count",
        "space_count",
        "slash_count",
        "dot_count",
        "quote_count",
        "angle_bracket_count",
        "percent_count",
        "equals_count",
        "hyphen_count",
        "entropy",

        # URI-specific counts
        "uri_special_char_count",
        "uri_digit_count",
        "uri_alpha_count",
        "uri_slash_count",
        "uri_backslash_count",
        "uri_dot_count",
        "uri_quote_count",
        "uri_angle_bracket_count",
        "uri_percent_count",
        "uri_equals_count",
        "uri_hyphen_count",
        "uri_entropy",

        # Query-specific counts
        "query_special_char_count",
        "query_digit_count",
        "query_alpha_count",
        "query_slash_count",
        "query_backslash_count",
        "query_dot_count",
        "query_quote_count",
        "query_angle_bracket_count",
        "query_percent_count",
        "query_equals_count",
        "query_ampersand_count",
        "query_semicolon_count",
        "query_hyphen_count",
        "query_entropy",

        # User-Agent-specific counts
        "ua_special_char_count",
        "ua_digit_count",
        "ua_alpha_count",
        "ua_slash_count",
        "ua_dot_count",
        "ua_quote_count",
        "ua_percent_count",
        "ua_hyphen_count",
        "ua_entropy",

        # Response / normalized metadata
        "status_code",
        "status_code_missing",
        "status_code_invalid",
        "response_size",
        "response_size_missing",
        "response_size_invalid",

        # Preprocessor evasion metadata
        "decode_depth",
        "decode_changed",
        "decode_depth_uri",
        "decode_changed_uri",
        "decode_depth_query",
        "decode_changed_query",
        "decode_depth_user_agent",
        "decode_changed_user_agent",
        "decode_limit_reached",
        "removed_control_chars",

        # Keyword / heuristic features
        "has_sql_keyword",
        "has_sqli_evasion_pattern",
        "has_xss_keyword",
        "has_path_traversal",
        "is_scanner_user_agent",

        # Version marker as numeric for sklearn compatibility
        "feature_schema_version",
    ]

    def extract(self, record: Mapping[str, Any]) -> Dict[str, int | float]:
        uri = self._text(record.get("normalized_uri"))
        query = self._text(record.get("normalized_query_string"))
        user_agent = self._text(record.get("normalized_user_agent"))
        request = self._text(record.get("normalized_request"))

        # Fallback for older preprocessor output or partial records.
        if not request:
            normalized_url = self._text(record.get("normalized_url"))
            method = self._text(record.get("normalized_method") or record.get("http_method")).lower()
            if not normalized_url:
                normalized_url = f"{uri}?{query}" if query else uri
            request = self._normalize_spaces(
                f"method={method} | url={normalized_url} | user_agent={user_agent}"
            )

        query_params = self._safe_parse_query(query)

        features: Dict[str, int | float] = {
            # Lengths
            "uri_length": len(uri),
            "query_length": len(query),
            "request_length": len(request),
            "user_agent_length": len(user_agent),

            # Query structure
            "param_count": len(query_params),
            "param_name_count": len({name for name, _value in query_params}),
            "avg_param_name_length": self._avg_len([name for name, _value in query_params]),
            "avg_param_value_length": self._avg_len([value for _name, value in query_params]),

            # Backward-compatible aggregate counts
            "special_char_count": self._count_special_chars(request),
            "digit_count": self._count_digits(request),
            "alpha_count": self._count_alpha(request),
            "space_count": self._count_space(request),
            "slash_count": request.count("/"),
            "dot_count": request.count("."),
            "quote_count": self._count_quotes(request),
            "angle_bracket_count": self._count_angle_brackets(request),
            "percent_count": request.count("%"),
            "equals_count": request.count("="),
            "hyphen_count": request.count("-"),
            "entropy": self._round_entropy(request),

            # URI-specific
            **self._field_count_features("uri", uri, include_ampersand=False),

            # Query-specific
            **self._field_count_features("query", query, include_ampersand=True),

            # User-Agent-specific
            **self._field_count_features("ua", user_agent, include_ampersand=False, include_backslash=False),

            # Response / data quality metadata
            "status_code": self._to_int(record.get("status_code")),
            "status_code_missing": int(self._to_bool(record.get("status_code_missing"))),
            "status_code_invalid": int(self._to_bool(record.get("status_code_invalid"))),
            "response_size": self._to_int(record.get("response_size")),
            "response_size_missing": int(self._to_bool(record.get("response_size_missing"))),
            "response_size_invalid": int(self._to_bool(record.get("response_size_invalid"))),

            # Preprocessor evasion metadata
            "decode_depth": self._to_int(record.get("decode_depth")),
            "decode_changed": int(self._to_bool(record.get("decode_changed"))),
            "decode_depth_uri": self._to_int(record.get("decode_depth_uri")),
            "decode_changed_uri": int(self._to_bool(record.get("decode_changed_uri"))),
            "decode_depth_query": self._to_int(record.get("decode_depth_query_string")),
            "decode_changed_query": int(self._to_bool(record.get("decode_changed_query_string"))),
            "decode_depth_user_agent": self._to_int(record.get("decode_depth_user_agent")),
            "decode_changed_user_agent": int(self._to_bool(record.get("decode_changed_user_agent"))),
            "decode_limit_reached": int(self._to_bool(record.get("decode_limit_reached"))),
            "removed_control_chars": int(self._to_bool(record.get("removed_control_chars"))),

            # Keyword / heuristic signals
            "has_sql_keyword": int(self._contains_any(request, self.SQL_KEYWORDS)),
            "has_sqli_evasion_pattern": int(self._has_sqli_evasion_pattern(query) or self._has_sqli_evasion_pattern(request)),
            "has_xss_keyword": int(self._contains_any(request, self.XSS_KEYWORDS)),
            "has_path_traversal": int(self._contains_any(request, self.TRAVERSAL_KEYWORDS)),
            "is_scanner_user_agent": int(self._is_scanner_user_agent(user_agent)),

            # Numeric schema version marker
            "feature_schema_version": 2,
        }

        # Enforce fixed schema and numeric-only vector.
        return {name: self._numeric(features.get(name, 0)) for name in self.FEATURE_NAMES}

    def enrich(self, record: Mapping[str, Any]) -> Dict[str, Any]:
        enriched = dict(record)
        for key, value in self.extract(record).items():
            enriched[f"feature_{key}"] = value
        enriched["feature_version"] = self.FEATURE_VERSION
        enriched["feature_names"] = list(self.FEATURE_NAMES)
        return enriched

    @classmethod
    def feature_names(cls) -> List[str]:
        return list(cls.FEATURE_NAMES)

    @staticmethod
    def _safe_parse_query(query: str):
        if not query:
            return []
        try:
            return parse_qsl(query, keep_blank_values=True)
        except Exception:
            return [tuple(part.split("=", 1)) if "=" in part else (part, "") for part in query.split("&") if part]

    def _field_count_features(
        self,
        prefix: str,
        value: str,
        *,
        include_ampersand: bool,
        include_backslash: bool = True,
    ) -> Dict[str, int | float]:
        features: Dict[str, int | float] = {
            f"{prefix}_special_char_count": self._count_special_chars(value),
            f"{prefix}_digit_count": self._count_digits(value),
            f"{prefix}_alpha_count": self._count_alpha(value),
            f"{prefix}_slash_count": value.count("/"),
            f"{prefix}_dot_count": value.count("."),
            f"{prefix}_quote_count": self._count_quotes(value),
            f"{prefix}_angle_bracket_count": self._count_angle_brackets(value),
            f"{prefix}_percent_count": value.count("%"),
            f"{prefix}_hyphen_count": value.count("-"),
            f"{prefix}_entropy": self._round_entropy(value),
        }
        if include_backslash:
            features[f"{prefix}_backslash_count"] = value.count("\\")
        if include_ampersand:
            features[f"{prefix}_equals_count"] = value.count("=")
            features[f"{prefix}_ampersand_count"] = value.count("&")
            features[f"{prefix}_semicolon_count"] = value.count(";")
        else:
            features[f"{prefix}_equals_count"] = value.count("=")
        return features

    def _count_special_chars(self, value: str) -> int:
        return sum(1 for ch in value if ch in self.SPECIAL_CHARS)

    @staticmethod
    def _count_digits(value: str) -> int:
        return sum(ch.isdigit() for ch in value)

    @staticmethod
    def _count_alpha(value: str) -> int:
        return sum(ch.isalpha() for ch in value)

    @staticmethod
    def _count_space(value: str) -> int:
        return sum(ch.isspace() for ch in value)

    @staticmethod
    def _count_quotes(value: str) -> int:
        return value.count("'") + value.count('"')

    @staticmethod
    def _count_angle_brackets(value: str) -> int:
        return value.count("<") + value.count(">")

    @classmethod
    def _contains_any(cls, value: str, keywords: Iterable[str]) -> bool:
        text = value.lower()
        return any(keyword.lower() in text for keyword in keywords)

    @classmethod
    def _has_sqli_evasion_pattern(cls, value: str) -> bool:
        if not value:
            return False
        return bool(cls.SQLI_EVASION_PATTERN.search(value) or cls.UNION_SELECT_PATTERN.search(value))

    @classmethod
    def _is_scanner_user_agent(cls, user_agent: str) -> bool:
        text = user_agent.lower()
        return any(scanner in text for scanner in cls.SCANNER_USER_AGENTS)

    @staticmethod
    def _to_int(value: Any) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _to_bool(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "y", "error"}
        return False

    @staticmethod
    def _text(value: Any) -> str:
        if value is None:
            return ""
        return str(value)

    @staticmethod
    def _normalize_spaces(value: str) -> str:
        return " ".join(str(value).split())

    @classmethod
    def _round_entropy(cls, value: str) -> float:
        return round(cls._entropy(value), 4)

    @staticmethod
    def _entropy(value: str) -> float:
        if not value:
            return 0.0

        frequencies: Dict[str, int] = {}
        for ch in value:
            frequencies[ch] = frequencies.get(ch, 0) + 1

        entropy = 0.0
        length = len(value)

        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)

        return entropy

    @staticmethod
    def _avg_len(values: Iterable[str]) -> float:
        values = list(values)
        if not values:
            return 0.0
        return round(sum(len(str(value)) for value in values) / len(values), 4)

    @staticmethod
    def _numeric(value: Any) -> int | float:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return value
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            return 0
        if numeric.is_integer():
            return int(numeric)
        return numeric
