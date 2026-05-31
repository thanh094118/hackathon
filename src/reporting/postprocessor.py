from collections import Counter
from typing import Dict, Iterable, List


class PostProcessor:
    """Aggregate run-level statistics from scored records and alerts."""

    def build_summary(
        self,
        *,
        input_path: str,
        server_type: str,
        output_dir: str,
        rules_path: str,
        raw_lines: List[Dict],
        parsed_logs: List[Dict],
        normalized_logs: List[Dict],
        preprocessed_requests: List[Dict],
        scored_records: List[Dict],
        ml_predictions: List[Dict] | None,
        alerts: List[Dict],
    ) -> Dict:
        parse_errors = sum(1 for row in parsed_logs if row.get("parse_error"))
        label_counts = Counter(row.get("final_label", "benign") for row in scored_records)
        alert_attack_types = Counter(
            row.get("attack_type")
            for row in alerts
            if row.get("attack_type")
        )
        ml_label_counts = Counter(
            str(row.get("ml_label", "")).lower()
            for row in (ml_predictions or [])
            if row.get("ml_label")
        )
        ml_attack_types = Counter(
            row.get("ml_attack_type")
            for row in (ml_predictions or [])
            if row.get("ml_attack_type")
        )
        rule_hits = Counter()
        detection_sources = Counter()
        for row in alerts:
            for rule_id in row.get("matched_rule_ids", []):
                if rule_id:
                    rule_hits[rule_id] += 1
            for source in row.get("detection_sources", []):
                if source:
                    detection_sources[str(source)] += 1

        return {
            "input_path": input_path,
            "server_type": server_type.lower(),
            "rules_path": rules_path,
            "output_dir": output_dir,
            "counts": {
                "raw_lines": len(raw_lines),
                "parsed_logs": len(parsed_logs),
                "normalized_logs": len(normalized_logs),
                "preprocessed_requests": len(preprocessed_requests),
                "scored_records": len(scored_records),
                "alerts": len(alerts),
                "parse_errors": parse_errors,
            },
            "labels": {
                "benign": label_counts.get("benign", 0),
                "suspicious": label_counts.get("suspicious", 0),
                "malicious": label_counts.get("malicious", 0),
            },
            "top_attack_types": alert_attack_types.most_common(5),
            "hybrid_detection": {
                "method": "hybrid",
                "alert_source_counts": dict(sorted(detection_sources.items())),
            },
            "ml": {
                "enabled": bool(ml_predictions),
                "prediction_count": len(ml_predictions or []),
                "labels": {
                    "benign": ml_label_counts.get("benign", 0),
                    "attack": ml_label_counts.get("attack", 0),
                },
                "top_attack_types": ml_attack_types.most_common(5),
            },
            "top_matched_rule_ids": rule_hits.most_common(10),
        }
