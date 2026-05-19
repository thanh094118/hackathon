from pathlib import Path
from typing import Iterator, List


class FileCollector:
    """
    Module 1: Log Collector.

    Reads raw access log lines from a single file.
    This MVP uses batch mode: the whole log file is read line by line.
    """

    def __init__(self, input_path: str):
        self.input_path = Path(input_path)

    def validate(self) -> None:
        if not self.input_path.exists():
            raise FileNotFoundError(f"Input log file not found: {self.input_path}")
        if not self.input_path.is_file():
            raise ValueError(f"Input path is not a file: {self.input_path}")

    def read_lines(self) -> Iterator[str]:
        """
        Yields non-empty log lines.

        Output:
            raw log line as string
        """
        self.validate()

        with self.input_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.strip():
                    yield line

    def read_all(self) -> List[str]:
        return list(self.read_lines())
