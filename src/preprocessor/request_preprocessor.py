import re
from typing import Dict
from urllib.parse import unquote_plus


class RequestPreprocessor:
    """
    Module 4: Request Preprocessor.

    - Decode URL-encoded payloads.
    - Convert text to lowercase.
    - Build normalized request text for rule detection and feature extraction.
    """

    MULTI_SPACE_PATTERN = re.compile(r"\s+")

    def preprocess(self, record: Dict) -> Dict:
        uri = record.get("uri") or ""
        query_string = record.get("query_string") or ""
        user_agent = record.get("user_agent") or ""
        http_method = record.get("http_method") or ""

        decoded_uri = self._safe_decode(uri)
        decoded_query = self._safe_decode(query_string)
        decoded_user_agent = self._safe_decode(user_agent)

        normalized_uri = self._normalize_text(decoded_uri)
        normalized_query = self._normalize_text(decoded_query)
        normalized_user_agent = self._normalize_text(decoded_user_agent)
        normalized_method = self._normalize_text(http_method)

        normalized_url = (
            f"{normalized_uri}?{normalized_query}"
            if normalized_query
            else normalized_uri
        )

        normalized_request = self._normalize_spaces(
            f"{normalized_method} {normalized_url} {normalized_user_agent}"
        )

        enriched = dict(record)
        enriched.update({
            "decoded_uri": decoded_uri,
            "decoded_query_string": decoded_query,
            "decoded_user_agent": decoded_user_agent,
            "normalized_uri": normalized_uri,
            "normalized_query_string": normalized_query,
            "normalized_user_agent": normalized_user_agent,
            "normalized_url": normalized_url,
            "normalized_request": normalized_request,
        })
        return enriched

    def _safe_decode(self, value: str, max_rounds: int = 2) -> str:
        if not value:
            return ""

        decoded = str(value)
        for _ in range(max_rounds):
            new_value = unquote_plus(decoded)
            if new_value == decoded:
                break
            decoded = new_value
        return decoded

    def _normalize_text(self, value: str) -> str:
        if not value:
            return ""
        value = value.lower()
        value = value.replace("\x00", "")
        return self._normalize_spaces(value)

    def _normalize_spaces(self, value: str) -> str:
        return self.MULTI_SPACE_PATTERN.sub(" ", value).strip()
