from dataclasses import dataclass
from typing import Dict


@dataclass
class RiskEngine:
    """
    Module 7: deterministic risk scoring and post-processing.

    Uses rule score as baseline and small explainable bonuses from handcrafted
    request features.
    """

    suspicious_threshold: int = 25
    malicious_threshold: int = 70

    def score(self, record: Dict) -> Dict:
        rule_score = self._to_int(record.get("rule_score"))
        bonus = 0

        if self._to_int(record.get("feature_has_sql_keyword")):
            bonus += 8
        if self._to_int(record.get("feature_has_xss_keyword")):
            bonus += 8
        if self._to_int(record.get("feature_has_path_traversal")):
            bonus += 8
        if self._to_int(record.get("feature_is_scanner_user_agent")):
            bonus += 6

        if self._to_int(record.get("feature_special_char_count")) >= 20:
            bonus += 4
        if self._to_int(record.get("feature_param_count")) >= 10:
            bonus += 3

        status_code = self._to_int(record.get("status_code"))
        if status_code >= 500:
            bonus += 3

        risk_score = min(100, rule_score + bonus)
        final_label = self._label_from_score(risk_score)

        return {
            "risk_score": risk_score,
            "risk_bonus": bonus,
            "risk_level": self._risk_level_from_score(risk_score),
            "final_label": final_label,
            "should_alert": final_label in {"suspicious", "malicious"},
        }

    def _label_from_score(self, score: int) -> str:
        if score >= self.malicious_threshold:
            return "malicious"
        if score >= self.suspicious_threshold:
            return "suspicious"
        return "benign"

    @staticmethod
    def _risk_level_from_score(score: int) -> str:
        if score >= 90:
            return "critical"
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        if score >= 25:
            return "low"
        return "none"

    @staticmethod
    def _to_int(value) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0
