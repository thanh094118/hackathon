from abc import ABC, abstractmethod
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
            parsed["line_number"] = line_number
            parsed["server_type"] = self.server_type
            parsed["raw_log"] = line
            records.append(parsed)
        return records
