from abc import ABC, abstractmethod
import hashlib
from typing import Dict, Iterable, List, Optional


class BaseParser(ABC):
    """
    Module 2: Base Parser.

    A parser converts one raw log line into a structured dictionary.
    """

    server_type: str = "unknown"

    @abstractmethod
    def parse_line(self, line: str) -> Optional[Dict]:
        pass

    def parse_lines(self, lines: Iterable[str]) -> List[Dict]:
        records = []
        for line_number, line in enumerate(lines, start=1):
            parsed = self.parse_line(line)
            if parsed is None:
                continue
            parsed.setdefault("parse_error", False)
            parsed.setdefault("error_message", None)
            parsed["parse_status"] = "error" if parsed.get("parse_error") else "success"
            parsed["line_number"] = line_number
            parsed["server_type"] = self.server_type
            parsed.setdefault("raw_log", line)
            parsed.setdefault("event_id", self._build_event_id(line_number=line_number, raw_log=parsed.get("raw_log", "")))
            if parsed.get("raw_uri") is not None:
                parsed.setdefault("original_url", parsed.get("raw_uri"))
            records.append(parsed)
        return records

    def _build_event_id(self, *, line_number: int, raw_log: str) -> str:
        digest = hashlib.sha1(str(raw_log).encode("utf-8", errors="ignore")).hexdigest()[:12]
        return f"{self.server_type}:{line_number}:{digest}"
