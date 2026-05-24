from pathlib import Path
from typing import Iterator, List, Tuple

from src.collector.collect_flow import AccessLogCollectFlow, AccessLogJob
from src.collector.read_flow import AccessLogReadFlow


class FileCollector:
    """
    Backward-compatible facade for Module 1 collector.

    Internally uses:
    - Flow 1: AccessLogCollectFlow (discover + byte-exact copy to outputs)
    - Flow 2: AccessLogReadFlow (decode + sanitize lines for parser pipeline)
    """

    def __init__(self, input_path: str):
        self.input_path = Path(input_path)

    def validate(self) -> None:
        AccessLogReadFlow(self.input_path).validate()

    def read_lines(self) -> Iterator[str]:
        return AccessLogReadFlow(self.input_path).read_lines()

    def read_all(self) -> List[str]:
        return AccessLogReadFlow(self.input_path).read_all()

    def collect_jobs(self, output_root: str) -> List[AccessLogJob]:
        return AccessLogCollectFlow(self.input_path).collect(output_root)

    def collect_access_logs_to_txt(self, output_root: str) -> List[Tuple[Path, Path]]:
        jobs = self.collect_jobs(output_root)
        return [(job.input_log_path, job.output_txt_path) for job in jobs]
