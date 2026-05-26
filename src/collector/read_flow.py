from pathlib import Path
from typing import Dict, Iterator, List


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
    def _decode_for_pipeline(raw_line: bytes) -> tuple[str, str, bool]:
        try:
            return raw_line.decode("utf-8"), "utf-8", False
        except UnicodeDecodeError:
            return raw_line.decode("latin-1"), "latin-1", True

    @staticmethod
    def _strip_utf8_bom_from_first_line(raw_line: bytes, is_first_line: bool) -> bytes:
        if is_first_line and raw_line.startswith(b"\xef\xbb\xbf"):
            return raw_line[3:]
        return raw_line

    @staticmethod
    def _is_continuation_line(line: str) -> bool:
        # Conservative merge strategy:
        # only treat indented lines as continuation payload.
        return line.startswith((" ", "\t"))

    def read_records(self) -> List[Dict]:
        self.validate()

        records: List[Dict] = []
        current_record: Dict | None = None
        is_first_line = True
        physical_line_number = 0

        with self.input_path.open("rb") as f:
            for raw_line in f:
                physical_line_number += 1
                had_bom = is_first_line and raw_line.startswith(b"\xef\xbb\xbf")
                raw_line = self._strip_utf8_bom_from_first_line(raw_line, is_first_line)
                is_first_line = False

                decoded_line, encoding_used, decode_error = self._decode_for_pipeline(raw_line)
                line = decoded_line.rstrip("\r\n")
                if not line.strip():
                    continue

                if current_record is None:
                    current_record = {
                        "line": line,
                        "encoding_used": encoding_used,
                        "decode_error": decode_error,
                        "had_bom": had_bom,
                        "was_continuation_merged": False,
                        "physical_line_start": physical_line_number,
                        "physical_line_end": physical_line_number,
                    }
                    continue

                if self._is_continuation_line(line):
                    current_record["line"] += "\\n" + line
                    current_record["was_continuation_merged"] = True
                    current_record["decode_error"] = bool(current_record["decode_error"] or decode_error)
                    current_record["physical_line_end"] = physical_line_number
                    # Track strongest signal for decode path.
                    if current_record["encoding_used"] != "latin-1" and encoding_used == "latin-1":
                        current_record["encoding_used"] = "latin-1"
                else:
                    records.append(current_record)
                    current_record = {
                        "line": line,
                        "encoding_used": encoding_used,
                        "decode_error": decode_error,
                        "had_bom": had_bom,
                        "was_continuation_merged": False,
                        "physical_line_start": physical_line_number,
                        "physical_line_end": physical_line_number,
                    }

        if current_record is not None:
            records.append(current_record)

        return records

    def read_lines(self) -> Iterator[str]:
        for record in self.read_records():
            yield record["line"]

    def read_all(self) -> List[str]:
        return [record["line"] for record in self.read_records()]
