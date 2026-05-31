from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple


@dataclass
class RiskEngine:
    """
    Module 7: deterministic hybrid risk scoring and post-processing.

    Rule detection and ML inference are treated as signals. This engine is the
    single place that merges those signals with handcrafted request features
    into the final alert verdict.
    """

    suspicious_threshold: int = 25
    malicious_threshold: int = 70

    def score(self, record: Dict) -> Dict:
        rule_score = self._to_int(record.get("rule_score"))
        ml_score = self._ml_score(record)

        rule_signal = self._has_rule_signal(record, rule_score)
        ml_signal = self._has_ml_signal(record)

        base_score = max(rule_score, ml_score)
        bonus = 0

        if self._to_int(record.get("feature_has_sql_keyword")):
            bonus += 8
        if self._to_int(record.get("feature_has_xss_keyword")):
            bonus += 8
        if self._to_int(record.get("feature_has_path_traversal")):
            bonus += 8
        if self._to_int(record.get("feature_is_scanner_user_agent")):
            bonus += 6

        special_char_total = (
            self._to_int(record.get("feature_uri_special_char_count"))
            + self._to_int(record.get("feature_query_special_char_count"))
            + self._to_int(record.get("feature_ua_special_char_count"))
        )
        if special_char_total >= 20:
            bonus += 4
        if self._to_int(record.get("feature_param_count")) >= 10:
            bonus += 3

        status_code = self._to_int(record.get("status_code"))
        if status_code >= 500:
            bonus += 3

        risk_score = min(100, base_score + bonus)
        final_label = self._label_from_score(risk_score)
        detection_sources = self._detection_sources(
            rule_signal=rule_signal,
            ml_signal=ml_signal,
            feature_bonus=bonus,
        )
        attack_type, attack_types = self._resolve_attack_types(
            record,
            rule_score=rule_score,
            ml_score=ml_score,
            ml_signal=ml_signal,
        )

        return {
            "detection_method": "hybrid",
            "detection_sources": detection_sources,
            "primary_signal": self._primary_signal(
                rule_score=rule_score,
                ml_score=ml_score,
                rule_signal=rule_signal,
                ml_signal=ml_signal,
                feature_bonus=bonus,
            ),
            "attack_type": attack_type,
            "attack_types": attack_types,
            "risk_score": risk_score,
            "risk_bonus": bonus,
            "risk_input_scores": {
                "rules": rule_score,
                "ml": ml_score,
                "features": bonus,
                "base": base_score,
            },
            "risk_level": self._risk_level_from_score(risk_score),
            "final_label": final_label,
            "should_alert": final_label in {"suspicious", "malicious"},
        }

    def _ml_score(self, record: Mapping[str, Any]) -> int:
        if not self._has_ml_signal(record):
            return 0

        for key in ("ml_attack_probability", "ml_confidence"):
            value = record.get(key)
            if value is None:
                continue
            try:
                score = float(value)
            except (TypeError, ValueError):
                continue
            if score <= 1.0:
                score *= 100
            return max(0, min(100, int(score)))

        return self.malicious_threshold

    @staticmethod
    def _has_rule_signal(record: Mapping[str, Any], rule_score: int) -> bool:
        label = str(record.get("rule_label") or "").strip().lower()
        return bool(
            rule_score > 0
            or record.get("matched_rule_ids")
            or label in {"suspicious", "malicious", "attack"}
        )

    @staticmethod
    def _has_ml_signal(record: Mapping[str, Any]) -> bool:
        label = str(record.get("ml_label") or "").strip().lower()
        return bool(
            record.get("ml_should_alert")
            or label in {"attack", "malicious", "suspicious"}
        )

    @staticmethod
    def _detection_sources(
        *,
        rule_signal: bool,
        ml_signal: bool,
        feature_bonus: int,
    ) -> List[str]:
        sources: List[str] = []
        if rule_signal:
            sources.append("rules")
        if ml_signal:
            sources.append("ml")
        if feature_bonus > 0:
            sources.append("features")
        return sources

    @staticmethod
    def _primary_signal(
        *,
        rule_score: int,
        ml_score: int,
        rule_signal: bool,
        ml_signal: bool,
        feature_bonus: int,
    ) -> str:
        if rule_signal and ml_signal and rule_score == ml_score:
            return "rules+ml"
        if rule_score >= ml_score and rule_signal:
            return "rules"
        if ml_score > rule_score and ml_signal:
            return "ml"
        if feature_bonus > 0:
            return "features"
        return "none"

    @classmethod
    def _resolve_attack_types(
        cls,
        record: Mapping[str, Any],
        *,
        rule_score: int,
        ml_score: int,
        ml_signal: bool,
    ) -> Tuple[Optional[str], List[str]]:
        rule_attack_type = cls._clean_attack_type(record.get("attack_type"))
        ml_attack_type = cls._clean_attack_type(record.get("ml_attack_type")) if ml_signal else None

        attack_types: List[str] = []
        raw_attack_types = record.get("attack_types")
        if isinstance(raw_attack_types, list):
            for value in raw_attack_types:
                cleaned = cls._clean_attack_type(value)
                if cleaned and cleaned not in attack_types:
                    attack_types.append(cleaned)

        for value in (rule_attack_type, ml_attack_type):
            if value and value not in attack_types:
                attack_types.append(value)

        if ml_attack_type and (ml_score > rule_score or not rule_attack_type):
            primary = ml_attack_type
        else:
            primary = rule_attack_type or ml_attack_type

        return primary, attack_types

    @staticmethod
    def _clean_attack_type(value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, list):
            if not value:
                return None
            value = value[0]
        text = str(value).strip()
        if not text:
            return None
        if text.lower() in {"unknown", "none", "normal", "benign"}:
            return None
        return text

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
