import csv
import json
from pathlib import Path
from typing import Any, Iterable, Mapping


class CSVExporter:
    """Write records to CSV with stable preferred columns first."""

    def __init__(self, preferred_fieldnames: list[str] | None = None):
        self.preferred_fieldnames = preferred_fieldnames or []

    def export(self, records: Iterable[Mapping[str, Any]], output_path: str | Path) -> None:
        rows = [self._flatten_record(record) for record in records]
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        if not rows:
            path.write_text("", encoding="utf-8")
            return

        all_keys = set()
        for row in rows:
            all_keys.update(row.keys())

        fieldnames = self.preferred_fieldnames + sorted(
            key for key in all_keys if key not in self.preferred_fieldnames
        )

        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)

    @staticmethod
    def _flatten_record(record: Mapping[str, Any]) -> dict[str, Any]:
        flattened = dict(record)
        for key, value in flattened.items():
            if isinstance(value, (dict, list, tuple)):
                flattened[key] = json.dumps(value, ensure_ascii=False)
        return flattened
