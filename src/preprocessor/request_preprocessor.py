from __future__ import annotations

import html
import re
import unicodedata
from typing import Any, Dict, Iterable, Optional
from urllib.parse import unquote, unquote_plus


class RequestPreprocessor:
    """
    Module 4: Request Preprocessor.

    Responsibilities:
    - Decode URL/path/query/User-Agent safely for detection.
    - Preserve field boundaries for rule engine and feature extraction.
    - Normalize Unicode and remove evasion control/format characters.
    - Track decode depth, changed flags, and preprocessing warnings/errors.

    Design notes:
    - URI/path uses urllib.parse.unquote(), because '+' is a literal char in path.
    - Query string uses urllib.parse.unquote_plus(), because '+' means space in
      application/x-www-form-urlencoded semantics.
    - HTML entity decoding is included to catch XSS forms such as &lt;script&gt;.
    - Unicode NFKC normalization maps fullwidth forms, e.g. ａｌｅｒｔ -> alert.
    """

    # Collapse all whitespace after dangerous/control character cleanup.
    MULTI_SPACE_PATTERN = re.compile(r"\s+")

    # ASCII control chars except common whitespace are removed explicitly.
    # \x7f = DEL. \xad = soft hyphen, commonly used for evasion.
    CONTROL_CHARS_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\xad]")

    DEFAULT_MAX_DECODE_ROUNDS = 5
    DEFAULT_MAX_FIELD_LENGTH = 200_000

    OUTPUT_FIELDS = [
        "decoded_uri",
        "decoded_query_string",
        "decoded_user_agent",
        "normalized_uri",
        "normalized_query_string",
        "normalized_user_agent",
        "normalized_method",
        "normalized_url",
        "normalized_request",
        "normalized_request_fields",
        "decode_depth_uri",
        "decode_depth_query_string",
        "decode_depth_user_agent",
        "decode_depth",
        "decode_changed_uri",
        "decode_changed_query_string",
        "decode_changed_user_agent",
        "decode_changed",
        "decode_limit_reached_uri",
        "decode_limit_reached_query_string",
        "decode_limit_reached_user_agent",
        "decode_limit_reached",
        "removed_control_chars_uri",
        "removed_control_chars_query_string",
        "removed_control_chars_user_agent",
        "removed_control_chars",
        "preprocess_status",
        "preprocess_errors",
    ]

    # These fields may be produced upstream by Normalizer and are safe to reuse/overwrite.
    ALLOWED_PREEXISTING_FIELDS = {
        "decoded_uri",
        "decoded_query_string",
    }

    # Existing values in these groups indicate potential double-preprocess or field clobbering.
    OVERWRITE_WARN_FIELDS = {
        # normalized_*
        "normalized_uri",
        "normalized_query_string",
        "normalized_user_agent",
        "normalized_method",
        "normalized_url",
        "normalized_request",
        "normalized_request_fields",
        # preprocess_*
        "preprocess_status",
        "preprocess_errors",
        # decode_depth_* and related decode/control metadata
        "decode_depth_uri",
        "decode_depth_query_string",
        "decode_depth_user_agent",
        "decode_depth",
        "decode_changed_uri",
        "decode_changed_query_string",
        "decode_changed_user_agent",
        "decode_changed",
        "decode_limit_reached_uri",
        "decode_limit_reached_query_string",
        "decode_limit_reached_user_agent",
        "decode_limit_reached",
        "removed_control_chars_uri",
        "removed_control_chars_query_string",
        "removed_control_chars_user_agent",
        "removed_control_chars",
    }

    def __init__(
        self,
        *,
        max_decode_rounds: int = DEFAULT_MAX_DECODE_ROUNDS,
        field_separator: str = " | ",
        max_field_length: int = DEFAULT_MAX_FIELD_LENGTH,
        overwrite_existing: bool = True,
    ) -> None:
        """
        Args:
            max_decode_rounds:
                Maximum number of mixed HTML-entity + percent decode rounds.
            field_separator:
                Separator used in normalized_request. 
            max_field_length:
                Safety guard for very large fields. 
            overwrite_existing:
                If False, raises ValueError when the input record already
                contains fields produced by this preprocessor. 
        """
        if max_decode_rounds <= 0:
            raise ValueError("max_decode_rounds must be > 0")
        if max_field_length <= 0:
            raise ValueError("max_field_length must be > 0")
        if not field_separator:
            raise ValueError("field_separator must not be empty")

        self.max_decode_rounds = max_decode_rounds
        self.field_separator = field_separator
        self.max_field_length = max_field_length
        self.overwrite_existing = overwrite_existing

    def preprocess(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Preprocess a normalized parser record.
        """
        preprocess_errors: list[str] = []

        if not self.overwrite_existing:
            conflicts = sorted(
                (set(record.keys()) & set(self.OUTPUT_FIELDS))
                - self.ALLOWED_PREEXISTING_FIELDS
            )
            if conflicts:
                raise ValueError(
                    "Record already contains preprocessor output fields: "
                    + ", ".join(conflicts)
                )
        elif set(record.keys()) & self.OVERWRITE_WARN_FIELDS:
            preprocess_errors.append("preprocess_fields_overwritten")

        uri = self._input_text(record.get("uri"), "uri", preprocess_errors)
        query_string = self._input_text(record.get("query_string"), "query_string", preprocess_errors)
        user_agent = self._input_text(record.get("user_agent"), "user_agent", preprocess_errors)
        http_method = self._input_text(record.get("http_method"), "http_method", preprocess_errors)

        decoded_uri, uri_meta = self._safe_decode_uri(uri)
        decoded_query, query_meta = self._safe_decode_query(query_string)
        decoded_user_agent, ua_meta = self._safe_decode_text(user_agent)

        normalized_uri, uri_norm_meta = self._normalize_text_with_meta(decoded_uri)
        normalized_query, query_norm_meta = self._normalize_text_with_meta(decoded_query)
        normalized_user_agent, ua_norm_meta = self._normalize_text_with_meta(decoded_user_agent)
        normalized_method, method_norm_meta = self._normalize_text_with_meta(http_method)

        normalized_url = (
            f"{normalized_uri}?{normalized_query}"
            if normalized_query
            else normalized_uri
        )

        normalized_request_fields = {
            "method": normalized_method,
            "url": normalized_url,
            "uri": normalized_uri,
            "query_string": normalized_query,
            "user_agent": normalized_user_agent,
        }

        normalized_request = self._normalize_spaces(
            self.field_separator.join(
                [
                    f"method={normalized_method}",
                    f"url={normalized_url}",
                    f"user_agent={normalized_user_agent}",
                ]
            )
        )

        decode_limit_reached = (
            uri_meta["limit_reached"]
            or query_meta["limit_reached"]
            or ua_meta["limit_reached"]
        )
        if uri_meta["limit_reached"]:
            preprocess_errors.append("decode_limit_reached_uri")
        if query_meta["limit_reached"]:
            preprocess_errors.append("decode_limit_reached_query_string")
        if ua_meta["limit_reached"]:
            preprocess_errors.append("decode_limit_reached_user_agent")

        removed_control_chars = (
            uri_norm_meta["removed_control_chars"]
            or query_norm_meta["removed_control_chars"]
            or ua_norm_meta["removed_control_chars"]
            or method_norm_meta["removed_control_chars"]
        )
        if uri_norm_meta["removed_control_chars"]:
            preprocess_errors.append("control_chars_removed_uri")
        if query_norm_meta["removed_control_chars"]:
            preprocess_errors.append("control_chars_removed_query_string")
        if ua_norm_meta["removed_control_chars"]:
            preprocess_errors.append("control_chars_removed_user_agent")
        if method_norm_meta["removed_control_chars"]:
            preprocess_errors.append("control_chars_removed_http_method")

        enriched = dict(record)
        enriched.update(
            {
                "decoded_uri": decoded_uri,
                "decoded_query_string": decoded_query,
                "decoded_user_agent": decoded_user_agent,
                "normalized_uri": normalized_uri,
                "normalized_query_string": normalized_query,
                "normalized_user_agent": normalized_user_agent,
                "normalized_method": normalized_method,
                "normalized_url": normalized_url,
                "normalized_request": normalized_request,
                "normalized_request_fields": normalized_request_fields,
                "decode_depth_uri": uri_meta["depth"],
                "decode_depth_query_string": query_meta["depth"],
                "decode_depth_user_agent": ua_meta["depth"],
                "decode_depth": max(
                    uri_meta["depth"],
                    query_meta["depth"],
                    ua_meta["depth"],
                ),
                "decode_changed_uri": uri_meta["changed"],
                "decode_changed_query_string": query_meta["changed"],
                "decode_changed_user_agent": ua_meta["changed"],
                "decode_changed": bool(
                    uri_meta["changed"]
                    or query_meta["changed"]
                    or ua_meta["changed"]
                ),
                "decode_limit_reached_uri": uri_meta["limit_reached"],
                "decode_limit_reached_query_string": query_meta["limit_reached"],
                "decode_limit_reached_user_agent": ua_meta["limit_reached"],
                "decode_limit_reached": bool(decode_limit_reached),
                "removed_control_chars_uri": uri_norm_meta["removed_control_chars"],
                "removed_control_chars_query_string": query_norm_meta["removed_control_chars"],
                "removed_control_chars_user_agent": ua_norm_meta["removed_control_chars"],
                "removed_control_chars": bool(removed_control_chars),
                "preprocess_status": "error" if preprocess_errors else "success",
                "preprocess_errors": preprocess_errors,
            }
        )
        return enriched

    def _safe_decode_uri(self, value: str) -> tuple[str, Dict[str, Any]]:
        return self._safe_decode(value, percent_decoder=unquote)

    def _safe_decode_query(self, value: str) -> tuple[str, Dict[str, Any]]:
        return self._safe_decode_query_mixed(value)

    def _safe_decode_query_mixed(self, value: str) -> tuple[str, Dict[str, Any]]:
        original = str(value or "")
        if not original:
            return "", {"depth": 0, "changed": False, "limit_reached": False}

        decoded = original
        depth = 0
        limit_reached = False

        for round_index in range(self.max_decode_rounds):
            decoder = unquote_plus if round_index == 0 else unquote
            new_value = self._decode_one_round(decoded, percent_decoder=decoder)

            if new_value == decoded:
                break

            decoded = new_value
            depth += 1

            if round_index == self.max_decode_rounds - 1:
                probe = self._decode_one_round(decoded, percent_decoder=unquote)
                limit_reached = probe != decoded

        return decoded, {
            "depth": depth,
            "changed": decoded != original,
            "limit_reached": limit_reached,
        }

    def _safe_decode_text(self, value: str) -> tuple[str, Dict[str, Any]]:
        return self._safe_decode(value, percent_decoder=unquote)

    def _safe_decode(
        self,
        value: str,
        *,
        percent_decoder,
    ) -> tuple[str, Dict[str, Any]]:
        original = str(value or "")
        if not original:
            return "", {"depth": 0, "changed": False, "limit_reached": False}

        decoded = original
        depth = 0
        limit_reached = False

        for round_index in range(self.max_decode_rounds):
            new_value = self._decode_one_round(decoded, percent_decoder=percent_decoder)

            if new_value == decoded:
                break

            decoded = new_value
            depth += 1

            if round_index == self.max_decode_rounds - 1:
                probe = self._decode_one_round(decoded, percent_decoder=percent_decoder)
                limit_reached = probe != decoded

        return decoded, {
            "depth": depth,
            "changed": decoded != original,
            "limit_reached": limit_reached,
        }

    @staticmethod
    def _decode_one_round(value: str, *, percent_decoder) -> str:
        html_decoded = html.unescape(value)
        return percent_decoder(html_decoded)

    def _normalize_text(self, value: str) -> str:
        normalized, _meta = self._normalize_text_with_meta(value)
        return normalized

    def _normalize_text_with_meta(self, value: str) -> tuple[str, Dict[str, bool]]:
        if not value:
            return "", {"removed_control_chars": False}

        before = str(value)
        text = unicodedata.normalize("NFKC", before)
        text = text.lower()

        text_after_ascii_control = self.CONTROL_CHARS_PATTERN.sub("", text)

        chars: list[str] = []
        removed_unicode_control_or_format = False
        for char in text_after_ascii_control:
            category = unicodedata.category(char)
            if category in {"Cc", "Cf"}:
                removed_unicode_control_or_format = True
                continue
            chars.append(char)

        cleaned = "".join(chars)
        normalized = self._normalize_spaces(cleaned)

        removed_control_chars = (
            text_after_ascii_control != text
            or removed_unicode_control_or_format
        )

        return normalized, {"removed_control_chars": removed_control_chars}

    def _normalize_spaces(self, value: str) -> str:
        if not value:
            return ""
        return self.MULTI_SPACE_PATTERN.sub(" ", str(value)).strip()

    def _input_text(self, value: Any, field_name: str, errors: list[str]) -> str:
        if value is None:
            return ""

        text = str(value)
        if len(text) > self.max_field_length:
            errors.append(f"{field_name}_truncated")
            return text[: self.max_field_length]
        return text
