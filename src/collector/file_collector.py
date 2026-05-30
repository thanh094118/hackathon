from pathlib import Path
from typing import Dict, Iterator, List

from src.collector.read_flow import AccessLogReadFlow


class FileCollector:
    """
    Facade for Module 1 collector read flow.

    The collector now only exposes read/parse preparation behavior used by the
    main pipeline.
    """

    def __init__(self, input_path: str):
        self.input_path = Path(input_path)
        self.reader = AccessLogReadFlow(self.input_path)

    def validate(self) -> None:
        self.reader.validate()

    def read_lines(self) -> Iterator[str]:
        return self.reader.read_lines()

    def read_all(self) -> List[str]:
        return self.reader.read_all()

    def read_records(self) -> List[Dict]:
        return self.reader.read_records()
