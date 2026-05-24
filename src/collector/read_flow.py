import re
from pathlib import Path
from typing import Iterator, List


class AccessLogReadFlow:
    """
    Flow 2 (Reader):
    - Read one access log in binary mode
    - Strip UTF-8 BOM at first line
    - Normalize line endings
    - Merge suspicious continuation lines (possible newline injection)
    """

    def __init__(self, input_path: str | Path):
        self.input_path = Path(input_path)

    def validate(self) -> None:
        if not self.input_path.exists():
            raise FileNotFoundError(f"Input log file not found: {self.input_path}")
        if not self.input_path.is_file():
            raise ValueError(f"Input path is not a file: {self.input_path}")

    @staticmethod
    def _decode_for_pipeline(raw_line: bytes) -> str:
        try:
            return raw_line.decode("utf-8")
        except UnicodeDecodeError:
            return raw_line.decode("latin-1")

    @staticmethod
    def _strip_utf8_bom_from_first_line(raw_line: bytes, is_first_line: bool) -> bytes:
        if is_first_line and raw_line.startswith(b"\xef\xbb\xbf"):
            return raw_line[3:]
        return raw_line

    @staticmethod
    def _is_suspicious_line(line: str) -> bool:
        return not re.match(r"^[\d\w:.\[\]-]", line.lstrip())

    def read_lines(self) -> Iterator[str]:
        self.validate()

        current_record: str | None = None
        is_first_line = True

        with self.input_path.open("rb") as f:
            for raw_line in f:
                raw_line = self._strip_utf8_bom_from_first_line(raw_line, is_first_line)
                is_first_line = False

                line = self._decode_for_pipeline(raw_line).rstrip("\r\n")
                if not line.strip():
                    continue

                if current_record is None:
                    current_record = line
                    continue

                if self._is_suspicious_line(line):
                    current_record += "\\n" + line
                else:
                    yield current_record
                    current_record = line

        if current_record is not None:
            yield current_record

    def read_all(self) -> List[str]:
        return list(self.read_lines())
