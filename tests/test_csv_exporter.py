import csv
from pathlib import Path

from src.exporters.csv_exporter import CSVExporter


def test_csv_exporter_handles_attack_payload_special_characters(tmp_path: Path):
    output_path = tmp_path / "payloads.csv"
    records = [
        {
            "event_id": "evt-1",
            "uri": '/search?q="x,y"\r\n<script>alert(1)</script>',
            "matched_rules": ["xss", "quoted,payload"],
        }
    ]

    CSVExporter().export(records, output_path)

    with output_path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == 1
    assert rows[0]["event_id"] == "evt-1"
    assert rows[0]["uri"] == records[0]["uri"]
    assert rows[0]["matched_rules"] == '["xss", "quoted,payload"]'
