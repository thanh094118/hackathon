from __future__ import annotations

import copy
import hashlib
import logging
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Pattern, Tuple

import yaml

logger = logging.getLogger(__name__)


class RuleDetector:
    """
    Module 5: Rule-based Detector.

    Loads detection rules from YAML and applies them to preprocessed web request fields.

    Key properties:
    - Validates rules at load time.
    - Caches compiled regex patterns.
    - Supports strict=True for CI/fail-fast and strict=False for production warn-and-skip.
    - Guards YAML file size and regex target size.
    - Records detector_errors instead of silently ignoring missing rule fields.
    - Uses max-per-category scoring + small multi-category bonus instead of raw sum.
    - Can return detection result only, or enrich the input record.
    """

    DEFAULT_RULES_PATH = "src/rules/attack_patterns.yaml"

    FIELD_MAP = {
        "request": "normalized_request",
        "query_string": "normalized_query_string",
        "query": "normalized_query_string",
        "uri": "normalized_uri",
        "path": "normalized_uri",
        "user_agent": "normalized_user_agent",
        "url": "normalized_url",
        "raw_uri": "raw_uri",
        "original_url": "original_url",
        "decoded_uri": "decoded_uri",
        "decoded_query_string": "decoded_query_string",
        "decode_depth": "decode_depth",
        "decode_changed": "decode_changed",
        "removed_control_chars": "removed_control_chars",
        "status_code": "status_code",
        "response_size": "response_size",
        "source_ip": "source_ip",
        "http_method": "http_method",
    }

    VALID_TYPES = {"contains", "regex"}
    VALID_SEVERITIES = {"none", "low", "medium", "high", "critical"}

    def __init__(
        self,
        rules_path: str | Path = DEFAULT_RULES_PATH,
        *,
        strict: bool = True,
        max_yaml_size_bytes: int = 10 * 1024 * 1024,
        max_target_length: int = 200_000,
        enrich: bool = False,
    ) -> None:
        if max_yaml_size_bytes <= 0:
            raise ValueError("max_yaml_size_bytes must be > 0")
        if max_target_length <= 0:
            raise ValueError("max_target_length must be > 0")

        self.rules_path = Path(rules_path)
        self.strict = strict
        self.max_yaml_size_bytes = max_yaml_size_bytes
        self.max_target_length = max_target_length
        self.enrich = enrich

        self.rules: Dict[str, List[Dict[str, Any]]] = {}
        self.rule_version: Optional[str] = None
        self.load_errors: List[str] = []
        self.reload_rules()

    def reload_rules(self) -> None:
        """
        Reload rules from YAML.

        Useful for long-running pipelines when the ruleset is updated by an
        orchestrator. In strict mode, invalid rules abort loading. In lenient
        mode, invalid rules are skipped and recorded in load_errors.
        """
        rules, load_errors, version = self._load_rules(self.rules_path)
        self.rules = rules
        self.load_errors = load_errors
        self.rule_version = version

    def detect(self, record: Dict[str, Any], *, enrich: Optional[bool] = None) -> Dict[str, Any]:
        """
        Detect attacks in a preprocessed record.

        Args:
            record:
                Input preprocessed record.
            enrich:
                If True, return a copy of record with detection fields added.
                If False, return detection result only. Defaults to self.enrich.

        Returns:
            Detection result or enriched record.
        """
        detector_errors: List[str] = []
        matched_rules: List[Dict[str, Any]] = []
        attack_types = set()
        max_severity_rank = 0

        for category, rules in self.rules.items():
            if not isinstance(rules, list):
                continue

            for rule in rules:
                matched, match_context = self._match_rule(record, rule, detector_errors)
                if not matched:
                    continue

                severity = str(rule.get("severity", "low")).lower()
                score = int(rule.get("score", 0))

                match_record = {
                    "id": rule.get("id"),
                    "category": category,
                    "description": rule.get("description", ""),
                    "score": score,
                    "severity": severity,
                    "field": rule.get("field"),
                    "actual_field": match_context.get("actual_field"),
                    "pattern": rule.get("pattern"),
                    "type": rule.get("type"),
                }
                if match_context.get("matched_text") is not None:
                    match_record["matched_text"] = match_context["matched_text"]
                matched_rules.append(match_record)

                attack_types.add(category)
                max_severity_rank = max(max_severity_rank, self._severity_rank(severity))

        score_by_category = self._score_by_category(matched_rules)
        severity_by_category = self._severity_by_category(matched_rules)
        rule_score = self._aggregate_score(score_by_category)
        primary_attack_type = self._choose_primary_attack_type(matched_rules)

        result = {
            "rule_label": self._label_from_score(rule_score),
            "rule_score": rule_score,
            "rule_severity": self._severity_from_rank(max_severity_rank),
            "attack_type": primary_attack_type,
            "attack_types": sorted(attack_types),
            "score_by_category": score_by_category,
            "severity_by_category": severity_by_category,
            "matched_rules": matched_rules,
            "matched_rule_ids": [r["id"] for r in matched_rules],
            "detector_status": "error" if detector_errors else "success",
            "detector_errors": detector_errors,
            "rule_version": self.rule_version,
        }

        should_enrich = self.enrich if enrich is None else enrich
        if should_enrich:
            enriched = dict(record)
            enriched.update(result)
            return enriched
        return result

    def _load_rules(self, path: Path) -> Tuple[Dict[str, List[Dict[str, Any]]], List[str], str]:
        if not path.exists():
            # Try fallback to data/labels if src/rules doesn't exist
            fallback = Path("data/labels/attack_patterns.yaml")
            if fallback.exists():
                path = fallback
            else:
                raise FileNotFoundError(f"Rule YAML file not found: {path}")

        size = path.stat().st_size
        if size > self.max_yaml_size_bytes:
            raise ValueError(
                f"Rule YAML file is too large: {path} has {size} bytes, "
                f"limit is {self.max_yaml_size_bytes}"
            )

        raw_text = path.read_text(encoding="utf-8")
        version = hashlib.sha1(raw_text.encode("utf-8", errors="ignore")).hexdigest()[:12]

        try:
            data = yaml.safe_load(raw_text) or {}
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML syntax in {path}: {exc}") from None

        if not isinstance(data, dict):
            raise ValueError(f"Invalid rule YAML format: {path}")

        validated, errors = self._validate_and_prepare_rules(data, path)
        return validated, errors, version

    def _validate_and_prepare_rules(
        self,
        rules_data: Mapping[str, Any],
        path: Path,
    ) -> Tuple[Dict[str, List[Dict[str, Any]]], List[str]]:
        seen_ids: set[str] = set()
        validated: Dict[str, List[Dict[str, Any]]] = {}
        errors: List[str] = []

        for category, rules in rules_data.items():
            if not isinstance(rules, list):
                message = f"Invalid rule group '{category}' in {path}: expected list"
                self._handle_rule_error(message, errors)
                continue

            validated[category] = []
            for idx, rule in enumerate(rules, start=1):
                try:
                    prepared = self._validate_one_rule(category, idx, rule, path, seen_ids)
                except ValueError as exc:
                    self._handle_rule_error(str(exc), errors)
                    continue

                validated[category].append(prepared)

        return validated, errors

    def _validate_one_rule(
        self,
        category: str,
        idx: int,
        rule: Any,
        path: Path,
        seen_ids: set[str],
    ) -> Dict[str, Any]:
        if not isinstance(rule, dict):
            raise ValueError(f"Invalid rule at {category}[{idx}] in {path}: expected object")

        required = {"id", "field", "type", "pattern", "score", "severity"}
        missing = [key for key in required if key not in rule]
        if missing:
            raise ValueError(f"Rule {category}[{idx}] missing required fields: {missing}")

        prepared = dict(rule)

        rule_id = str(prepared.get("id") or "").strip()
        if not rule_id:
            raise ValueError(f"Rule {category}[{idx}] has empty id")
        if rule_id in seen_ids:
            raise ValueError(f"Duplicate rule id detected: {rule_id}")
        seen_ids.add(rule_id)
        prepared["id"] = rule_id

        rule_type = str(prepared.get("type")).lower().strip()
        if rule_type not in self.VALID_TYPES:
            raise ValueError(f"Rule {rule_id} has invalid type: {rule_type}")
        prepared["type"] = rule_type

        severity = str(prepared.get("severity")).lower().strip()
        if severity not in self.VALID_SEVERITIES:
            raise ValueError(f"Rule {rule_id} has invalid severity: {severity}")
        prepared["severity"] = severity

        try:
            score = int(prepared.get("score"))
        except (TypeError, ValueError):
            raise ValueError(f"Rule {rule_id} has non-integer score") from None
        if score < 0:
            raise ValueError(f"Rule {rule_id} has negative score")
        prepared["score"] = score

        field = str(prepared.get("field") or "").strip()
        if not field:
            raise ValueError(f"Rule {rule_id} has empty field")
        prepared["field"] = field

        pattern = str(prepared.get("pattern") or "")
        if not pattern:
            raise ValueError(f"Rule {rule_id} has empty pattern")
        prepared["pattern"] = pattern

        if rule_type == "regex":
            try:
                prepared["_compiled"] = re.compile(pattern, flags=re.IGNORECASE)
            except re.error as exc:
                raise ValueError(f"Rule {rule_id} has invalid regex pattern: {exc}") from None
            # Heuristic guard for patterns with obvious nested quantifier forms.
            if self._looks_redos_risky(pattern):
                message = f"Rule {rule_id} regex may be ReDoS-prone: {pattern}"
                self._handle_redos_risk(message)
                prepared["_redos_warning"] = message

        return prepared

    def _handle_rule_error(self, message: str, errors: List[str]) -> None:
        if self.strict:
            raise ValueError(message)
        errors.append(message)
        logger.warning("Skipping invalid rule: %s", message)

    def _handle_redos_risk(self, message: str) -> None:
        if self.strict:
            raise ValueError(message)
        logger.warning(message)

    @staticmethod
    def _looks_redos_risky(pattern: str) -> bool:
        """
        Lightweight heuristic for common catastrophic backtracking forms.
        """
        compact = pattern.replace(" ", "")
        simple_nested_quantifier = re.compile(
            r"\((?:\?:)?[A-Za-z0-9_.\\\[\]\^\$-]*[+*][A-Za-z0-9_.\\\[\]\^\$-]*\)[+*]"
        )
        counted_nested_quantifier = re.compile(
            r"\((?:\?:)?[A-Za-z0-9_.\\\[\]\^\$-]*\{\d+(?:,\d*)?\}[A-Za-z0-9_.\\\[\]\^\$-]*\)[+*]"
        )
        return bool(
            simple_nested_quantifier.search(compact)
            or counted_nested_quantifier.search(compact)
        )

    def _match_rule(
        self,
        record: Mapping[str, Any],
        rule: Mapping[str, Any],
        detector_errors: List[str],
    ) -> Tuple[bool, Dict[str, Any]]:
        field = str(rule.get("field", "request"))
        rule_type = str(rule.get("type", "contains")).lower()
        pattern = str(rule.get("pattern", ""))
        target, actual_key, field_found = self._get_target_text(record, field)

        if not field_found:
            rule_id = rule.get("id", "<unknown>")
            detector_errors.append(f"field_missing:{rule_id}:{actual_key}")
            return False, {"actual_field": actual_key}

        if target and len(target) > self.max_target_length:
            rule_id = rule.get("id", "<unknown>")
            detector_errors.append(f"target_truncated:{rule_id}:{actual_key}")
            target = target[: self.max_target_length]

        if not target or not pattern:
            return False, {"actual_field": actual_key}

        if rule_type == "contains":
            found = pattern.lower() in target.lower()
            matched_text = pattern if found else None
            return found, {"actual_field": actual_key, "matched_text": matched_text}

        if rule_type == "regex":
            compiled: Optional[Pattern[str]] = rule.get("_compiled")  # type: ignore[assignment]
            if not compiled:
                detector_errors.append(f"regex_not_compiled:{rule.get('id', '<unknown>')}")
                return False, {"actual_field": actual_key}
            try:
                match = compiled.search(target)
            except re.error as exc:
                detector_errors.append(f"regex_runtime_error:{rule.get('id', '<unknown>')}:{exc}")
                return False, {"actual_field": actual_key}

            return match is not None, {
                "actual_field": actual_key,
                "matched_text": match.group(0)[:200] if match else None,
            }

        detector_errors.append(f"unsupported_rule_type:{rule.get('id', '<unknown>')}:{rule_type}")
        return False, {"actual_field": actual_key}

    @classmethod
    def _get_target_text(cls, record: Mapping[str, Any], field: str) -> Tuple[str, str, bool]:
        actual_key = cls.FIELD_MAP.get(field, field)
        if actual_key not in record:
            return "", actual_key, False
        value = record.get(actual_key)
        if value is None:
            return "", actual_key, True
        return str(value), actual_key, True

    @classmethod
    def _score_by_category(cls, matched_rules: Iterable[Mapping[str, Any]]) -> Dict[str, int]:
        """
        Score aggregation:
        - Use max score per category instead of raw sum of all rules.
        """
        score_by_category: Dict[str, int] = {}
        for rule in matched_rules:
            category = str(rule["category"])
            score = int(rule.get("score", 0))
            score_by_category[category] = max(score_by_category.get(category, 0), score)
        return dict(sorted(score_by_category.items()))

    @classmethod
    def _severity_by_category(cls, matched_rules: Iterable[Mapping[str, Any]]) -> Dict[str, str]:
        rank_by_category: Dict[str, int] = {}
        for rule in matched_rules:
            category = str(rule["category"])
            rank_by_category[category] = max(
                rank_by_category.get(category, 0),
                cls._severity_rank(str(rule.get("severity", "none"))),
            )
        return {
            category: cls._severity_from_rank(rank)
            for category, rank in sorted(rank_by_category.items())
        }

    @staticmethod
    def _aggregate_score(score_by_category: Mapping[str, int]) -> int:
        if not score_by_category:
            return 0
        base = sum(score_by_category.values())
        multi_category_bonus = 10 * max(0, len(score_by_category) - 1)
        return min(base + multi_category_bonus, 100)

    @staticmethod
    def _severity_rank(severity: str) -> int:
        return {
            "none": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }.get(str(severity).lower(), 0)

    @staticmethod
    def _severity_from_rank(rank: int) -> str:
        if rank >= 4:
            return "critical"
        if rank == 3:
            return "high"
        if rank == 2:
            return "medium"
        if rank == 1:
            return "low"
        return "none"

    @staticmethod
    def _label_from_score(score: int) -> str:
        if score >= 70:
            return "malicious"
        if score >= 25:
            return "suspicious"
        return "benign"

    @classmethod
    def _choose_primary_attack_type(cls, matched_rules: List[Dict[str, Any]]) -> Optional[str]:
        if not matched_rules:
            return None

        score_by_category = cls._score_by_category(matched_rules)
        if not score_by_category:
            return None

        severity_by_category = cls._severity_by_category(matched_rules)

        def sort_key(item: Tuple[str, int]) -> Tuple[int, int, str]:
            category, score = item
            severity_rank = cls._severity_rank(severity_by_category.get(category, "none"))
            return score, severity_rank, category

        return max(score_by_category.items(), key=sort_key)[0]
