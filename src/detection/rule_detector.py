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

        return data

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
            return re.search(str(pattern), target, flags=re.IGNORECASE) is not None

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
