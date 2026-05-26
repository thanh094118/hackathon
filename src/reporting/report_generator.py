from datetime import datetime, timezone
from typing import Dict, List


class ReportGenerator:
    """Generate markdown report for one pipeline run."""

    def generate(self, summary: Dict, alerts: List[Dict]) -> str:
        now = datetime.now(timezone.utc).isoformat()
        counts = summary.get("counts", {})
        labels = summary.get("labels", {})

        lines = [
            "# Web Attack Detection Report",
            "",
            f"- Generated at (UTC): `{now}`",
            f"- Input file: `{summary.get('input_path')}`",
            f"- Server type: `{summary.get('server_type')}`",
            f"- Rules file: `{summary.get('rules_path')}`",
            f"- Output dir: `{summary.get('output_dir')}`",
            "",
            "## Pipeline Summary",
            "",
            f"- Raw lines: **{counts.get('raw_lines', 0)}**",
            f"- Parsed logs: **{counts.get('parsed_logs', 0)}**",
            f"- Parse errors: **{counts.get('parse_errors', 0)}**",
            f"- Normalized logs: **{counts.get('normalized_logs', 0)}**",
            f"- Preprocessed requests: **{counts.get('preprocessed_requests', 0)}**",
            f"- Scored records: **{counts.get('scored_records', 0)}**",
            f"- Alerts: **{counts.get('alerts', 0)}**",
            "",
            "## Label Distribution",
            "",
            f"- Benign: **{labels.get('benign', 0)}**",
            f"- Suspicious: **{labels.get('suspicious', 0)}**",
            f"- Malicious: **{labels.get('malicious', 0)}**",
            "",
            "## Top Attack Types",
            "",
        ]

        for attack_type, count in summary.get("top_attack_types", []):
            lines.append(f"- `{attack_type}`: **{count}**")
        if not summary.get("top_attack_types"):
            lines.append("- None")

        lines.extend(
            [
                "",
                "## Top Matched Rule IDs",
                "",
            ]
        )
        for rule_id, count in summary.get("top_matched_rule_ids", []):
            lines.append(f"- `{rule_id}`: **{count}**")
        if not summary.get("top_matched_rule_ids"):
            lines.append("- None")

        lines.extend(
            [
                "",
                "## Sample Alerts",
                "",
            ]
        )

        for alert in alerts[:10]:
            source_ip = alert.get("source_ip") or "-"
            method = alert.get("http_method") or "-"
            uri = alert.get("uri") or "-"
            label = alert.get("final_label") or alert.get("rule_label") or "-"
            score = alert.get("risk_score", alert.get("rule_score", 0))
            attack_type = alert.get("attack_type") or "-"
            lines.append(
                f"- `{source_ip}` `{method}` `{uri}` => `{label}` "
                f"(risk_score={score}, attack_type={attack_type})"
            )

        if not alerts:
            lines.append("- No suspicious or malicious alerts generated.")

        return "\n".join(lines) + "\n"
