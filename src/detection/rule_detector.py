import re
from pathlib import Path
from typing import Dict, List, Optional

import yaml


class RuleDetector:
    """
    Module 5: Rule-based Detector.

    Loads detection rules from YAML and applies them to preprocessed web request fields.
    """

    def __init__(self, rules_path: str = "data/labels/attack_patterns.yaml"):
        self.rules_path = Path(rules_path)
        self.rules = self._load_rules(self.rules_path)

    def detect(self, record: Dict) -> Dict:
        matched_rules: List[Dict] = []
        attack_types = set()
        total_score = 0
        max_severity_rank = 0

        for category, rules in self.rules.items():
            if not isinstance(rules, list):
                continue

            for rule in rules:
                if self._match_rule(record, rule):
                    severity = rule.get("severity", "low")
                    score = int(rule.get("score", 0))

                    matched_rules.append({
                        "id": rule.get("id"),
                        "category": category,
                        "description": rule.get("description", ""),
                        "score": score,
                        "severity": severity,
                        "field": rule.get("field"),
                        "pattern": rule.get("pattern"),
                    })

                    attack_types.add(category)
                    total_score += score
                    max_severity_rank = max(
                        max_severity_rank,
                        self._severity_rank(severity)
                    )

        rule_score = min(total_score, 100)
        return {
            "rule_label": self._label_from_score(rule_score),
            "rule_score": rule_score,
            "rule_severity": self._severity_from_rank(max_severity_rank),
            "attack_type": self._choose_primary_attack_type(matched_rules),
            "attack_types": sorted(attack_types),
            "matched_rules": matched_rules,
            "matched_rule_ids": [r["id"] for r in matched_rules],
        }

    def _load_rules(self, path: Path) -> Dict:
        if not path.exists():
            raise FileNotFoundError(f"Rule YAML file not found: {path}")

        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        if not isinstance(data, dict):
            raise ValueError(f"Invalid rule YAML format: {path}")

        self._validate_rules(data, path)
        return data

    def _validate_rules(self, rules_data: Dict, path: Path) -> None:
        valid_types = {"contains", "regex"}
        valid_severities = {"none", "low", "medium", "high", "critical"}
        seen_ids = set()

        for category, rules in rules_data.items():
            if not isinstance(rules, list):
                raise ValueError(f"Invalid rule group '{category}' in {path}: expected list")

            for idx, rule in enumerate(rules, start=1):
                if not isinstance(rule, dict):
                    raise ValueError(f"Invalid rule at {category}[{idx}] in {path}: expected object")

                required = {"id", "field", "type", "pattern", "score", "severity"}
                missing = [key for key in required if key not in rule]
                if missing:
                    raise ValueError(f"Rule {category}[{idx}] missing required fields: {missing}")

                rule_id = str(rule.get("id"))
                if not rule_id:
                    raise ValueError(f"Rule {category}[{idx}] has empty id")
                if rule_id in seen_ids:
                    raise ValueError(f"Duplicate rule id detected: {rule_id}")
                seen_ids.add(rule_id)

                rule_type = str(rule.get("type")).lower()
                if rule_type not in valid_types:
                    raise ValueError(f"Rule {rule_id} has invalid type: {rule_type}")

                severity = str(rule.get("severity")).lower()
                if severity not in valid_severities:
                    raise ValueError(f"Rule {rule_id} has invalid severity: {severity}")

                try:
                    score = int(rule.get("score"))
                except (TypeError, ValueError):
                    raise ValueError(f"Rule {rule_id} has non-integer score") from None
                if score < 0:
                    raise ValueError(f"Rule {rule_id} has negative score")

                pattern = str(rule.get("pattern"))
                if not pattern:
                    raise ValueError(f"Rule {rule_id} has empty pattern")

                if rule_type == "regex":
                    try:
                        re.compile(pattern, flags=re.IGNORECASE)
                    except re.error as exc:
                        raise ValueError(f"Rule {rule_id} has invalid regex pattern: {exc}") from None

    def _match_rule(self, record: Dict, rule: Dict) -> bool:
        field = rule.get("field", "request")
        rule_type = rule.get("type", "contains")
        pattern = rule.get("pattern", "")
        target = self._get_target_text(record, field)

        if not target or not pattern:
            return False

        if rule_type == "contains":
            return str(pattern).lower() in target.lower()

        if rule_type == "regex":
            try:
                return re.search(str(pattern), target, flags=re.IGNORECASE) is not None
            except re.error:
                return False

        return False

    @staticmethod
    def _get_target_text(record: Dict, field: str) -> str:
        field_map = {
            "request": "normalized_request",
            "query_string": "normalized_query_string",
            "uri": "normalized_uri",
            "user_agent": "normalized_user_agent",
            "url": "normalized_url",
        }
        actual_key = field_map.get(field, field)
        return str(record.get(actual_key, "") or "")

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

    @staticmethod
    def _choose_primary_attack_type(matched_rules: List[Dict]) -> Optional[str]:
        if not matched_rules:
            return None

        score_by_category: Dict[str, int] = {}
        for rule in matched_rules:
            category = rule["category"]
            score_by_category[category] = score_by_category.get(category, 0) + rule["score"]

        return max(score_by_category.items(), key=lambda item: item[1])[0]
