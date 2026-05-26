import math
from typing import Dict
from urllib.parse import parse_qsl


class FeatureExtractor:
    """
    Module 6: Feature Extractor.

    Converts a normalized/preprocessed request into hand-crafted numeric features.
    Module 7 AI/NLP is intentionally not implemented yet.
    """

    SQL_KEYWORDS = [
        "select", "union", "insert", "update", "delete", "drop",
        "information_schema", "sleep(", "benchmark(", "or 1=1"
    ]

    XSS_KEYWORDS = [
        "<script", "onerror=", "onload=", "javascript:", "document.cookie"
    ]

    TRAVERSAL_KEYWORDS = [
        "../", "..\\", "/etc/passwd", "win.ini", "boot.ini"
    ]

    SPECIAL_CHARS = set("'\"<>;(){}[]../\\=%-&|")

    def extract(self, record: Dict) -> Dict:
        uri = record.get("normalized_uri") or ""
        query = record.get("normalized_query_string") or ""
        user_agent = record.get("normalized_user_agent") or ""
        request = record.get("normalized_request") or ""

        query_params = self._safe_parse_query(query)

        return {
            "uri_length": len(uri),
            "query_length": len(query),
            "request_length": len(request),
            "user_agent_length": len(user_agent),
            "param_count": len(query_params),
            "special_char_count": self._count_special_chars(request),
            "digit_count": sum(ch.isdigit() for ch in request),
            "alpha_count": sum(ch.isalpha() for ch in request),
            "space_count": sum(ch.isspace() for ch in request),
            "slash_count": request.count("/"),
            "dot_count": request.count("."),
            "quote_count": request.count("'") + request.count('"'),
            "angle_bracket_count": request.count("<") + request.count(">"),
            "percent_count": request.count("%"),
            "equals_count": request.count("="),
            "hyphen_count": request.count("-"),
            "entropy": round(self._entropy(request), 4),
            "status_code": self._to_int(record.get("status_code")),
            "response_size": self._to_int(record.get("response_size")),
            "has_sql_keyword": int(self._contains_any(request, self.SQL_KEYWORDS)),
            "has_xss_keyword": int(self._contains_any(request, self.XSS_KEYWORDS)),
            "has_path_traversal": int(self._contains_any(request, self.TRAVERSAL_KEYWORDS)),
            "is_scanner_user_agent": int(self._is_scanner_user_agent(user_agent)),
        }

    def enrich(self, record: Dict) -> Dict:
        enriched = dict(record)
        for key, value in self.extract(record).items():
            enriched[f"feature_{key}"] = value
        return enriched

    @staticmethod
    def _safe_parse_query(query: str):
        if not query:
            return []
        try:
            return parse_qsl(query, keep_blank_values=True)
        except Exception:
            return [part for part in query.split("&") if part]

    def _count_special_chars(self, value: str) -> int:
        return sum(1 for ch in value if ch in self.SPECIAL_CHARS)

    @staticmethod
    def _contains_any(value: str, keywords) -> bool:
        value = value.lower()
        return any(keyword.lower() in value for keyword in keywords)

    @staticmethod
    def _is_scanner_user_agent(user_agent: str) -> bool:
        scanners = [
            "sqlmap", "nikto", "acunetix", "nessus", "openvas",
            "nmap", "gobuster", "ffuf", "dirbuster"
        ]
        user_agent = user_agent.lower()
        return any(scanner in user_agent for scanner in scanners)

    @staticmethod
    def _to_int(value) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _entropy(value: str) -> float:
        if not value:
            return 0.0

        frequencies = {}
        for ch in value:
            frequencies[ch] = frequencies.get(ch, 0) + 1

        entropy = 0.0
        length = len(value)

        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)

        return entropy
