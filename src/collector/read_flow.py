from pathlib import Path
from typing import Dict, Iterator, List, Tuple


class AccessLogReadFlow:
    """
    Flow 2 (Reader):
    - Read one access log in binary mode
    - Strip UTF-8 BOM at first line
    - Normalize line endings
    - Merge indented continuation lines only (possible newline injection)
    """

    def __init__(self, input_path: str | Path):
        self.input_path = Path(input_path)

    _CHUNK_SIZE = 1024 * 1024
    _UTF8_BOM = b"\xef\xbb\xbf"
    _FLAG_DECODE_FALLBACK_LATIN1 = "decode_fallback_latin1"
    _FLAG_HAD_UTF8_BOM = "had_utf8_bom"
    _FLAG_CONTINUATION_MERGED = "continuation_merged"

    def validate(self) -> None:
        if not self.input_path.exists():
            raise FileNotFoundError(f"Input log file not found: {self.input_path}")
        if not self.input_path.is_file():
            raise ValueError(f"Input path is not a file: {self.input_path}")

    @staticmethod
    def _decode_for_pipeline(raw_line: bytes) -> tuple[str, bool]:
        try:
            return raw_line.decode("utf-8"), False
        except UnicodeDecodeError:
            return raw_line.decode("latin-1"), True

    @staticmethod
    def _strip_utf8_bom_from_first_line(raw_line: bytes, is_first_line: bool) -> bytes:
        if is_first_line and raw_line.startswith(AccessLogReadFlow._UTF8_BOM):
            return raw_line[3:]
        return raw_line

    @staticmethod
    def _is_continuation_line(line: str) -> bool:
        # Conservative merge strategy:
        # only treat indented lines as continuation payload.
        return line.startswith((" ", "\t"))

    @classmethod
    def _iter_physical_lines(cls, handle) -> Iterator[bytes]:
        """
        Iterate physical lines in binary mode with CRLF/LF/CR support.

        Python's native binary iteration splits only on LF, so CR-only files would
        otherwise collapse into one very long line.
        """
        buffer = b""
        while True:
            chunk = handle.read(cls._CHUNK_SIZE)
            if not chunk:
                break
            buffer += chunk

            start = 0
            idx = 0
            buffer_len = len(buffer)
            while idx < buffer_len:
                marker = buffer[idx]

                if marker == 0x0A:  # \n
                    yield buffer[start:idx + 1]
                    idx += 1
                    start = idx
                    continue

                if marker == 0x0D:  # \r
                    if idx + 1 >= buffer_len:
                        # Wait for next chunk to confirm whether CRLF.
                        break
                    if buffer[idx + 1] == 0x0A:
                        yield buffer[start:idx + 2]
                        idx += 2
                    else:
                        yield buffer[start:idx + 1]
                        idx += 1
                    start = idx
                    continue

                idx += 1

            buffer = buffer[start:]

        if buffer:
            yield buffer

    def _iter_decoded_nonempty_physical_lines(
        self,
    ) -> Iterator[Tuple[str, bool, bool, int]]:
        self.validate()

        is_first_line = True
        physical_line_number = 0
        with self.input_path.open("rb") as handle:
            for raw_line in self._iter_physical_lines(handle):
                physical_line_number += 1

                had_bom = is_first_line and raw_line.startswith(self._UTF8_BOM)
                raw_line = self._strip_utf8_bom_from_first_line(raw_line, is_first_line)
                is_first_line = False

                decoded_line, decode_error = self._decode_for_pipeline(raw_line)
                line = decoded_line.rstrip("\r\n")
                if not line.strip():
                    continue

                yield line, decode_error, had_bom, physical_line_number

    @classmethod
    def _record_flags(
        cls,
        *,
        had_bom: bool,
        decode_fallback: bool,
        continuation_merged: bool,
    ) -> List[str]:
        flags: List[str] = []
        if had_bom:
            flags.append(cls._FLAG_HAD_UTF8_BOM)
        if decode_fallback:
            flags.append(cls._FLAG_DECODE_FALLBACK_LATIN1)
        if continuation_merged:
            flags.append(cls._FLAG_CONTINUATION_MERGED)
        return flags

    def _iter_logical_entries(self) -> Iterator[Tuple[str, List[str], List[int]]]:
        current_line: str | None = None
        current_flags: set[str] = set()
        current_start: int | None = None
        current_end: int | None = None

        for (
            line,
            decode_error,
            had_bom,
            physical_line_number,
        ) in self._iter_decoded_nonempty_physical_lines():
            if current_line is None:
                current_line = line
                current_start = physical_line_number
                current_end = physical_line_number
                current_flags = set(
                    self._record_flags(
                        had_bom=had_bom,
                        decode_fallback=decode_error,
                        continuation_merged=False,
                    )
                )
                continue

            if self._is_continuation_line(line):
                current_line += "\\n" + line
                current_flags.add(self._FLAG_CONTINUATION_MERGED)
                if decode_error:
                    current_flags.add(self._FLAG_DECODE_FALLBACK_LATIN1)
                current_end = physical_line_number
            else:
                assert current_start is not None and current_end is not None
                yield (
                    current_line,
                    [
                        flag
                        for flag in (
                            self._FLAG_HAD_UTF8_BOM,
                            self._FLAG_DECODE_FALLBACK_LATIN1,
                            self._FLAG_CONTINUATION_MERGED,
                        )
                        if flag in current_flags
                    ],
                    [current_start, current_end],
                )
                current_line = line
                current_start = physical_line_number
                current_end = physical_line_number
                current_flags = set(
                    self._record_flags(
                        had_bom=had_bom,
                        decode_fallback=decode_error,
                        continuation_merged=False,
                    )
                )

        if current_line is not None:
            assert current_start is not None and current_end is not None
            yield (
                current_line,
                [
                    flag
                    for flag in (
                        self._FLAG_HAD_UTF8_BOM,
                        self._FLAG_DECODE_FALLBACK_LATIN1,
                        self._FLAG_CONTINUATION_MERGED,
                    )
                    if flag in current_flags
                ],
                [current_start, current_end],
            )

    def read_records(self) -> List[Dict]:
        return [
            {
                "line": line,
                "flags": flags,
                "physical_line_range": physical_line_range,
            }
            for line, flags, physical_line_range in self._iter_logical_entries()
        ]

    def read_lines(self) -> Iterator[str]:
        for line, _, _ in self._iter_logical_entries():
            yield line

    def read_all(self) -> List[str]:
        return list(self.read_lines())
