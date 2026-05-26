import json
from pathlib import Path
from typing import Any, Iterable, Mapping


class JSONLExporter:
    """Write iterable records to JSON Lines."""

    def export(self, records: Iterable[Mapping[str, Any]], output_path: str | Path) -> None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(dict(record), ensure_ascii=False) + "\n")
