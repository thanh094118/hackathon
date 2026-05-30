from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List


SERVER_TYPE_FOLDERS = {"apache", "nginx", "iis"}


@dataclass(frozen=True)
class AccessLogJob:
    input_log_path: Path
    server_type: str
    output_dir: Path
    output_txt_path: Path


class AccessLogCollectFlow:
    """
    Flow 1 (Collector):
    - Discover all access*.log files
    - Copy each file byte-exact to outputs/<Server>/<access_name>/<access_name>.txt
    - Write log.txt warnings when non-UTF-8 or read/write errors are detected
    """

    def __init__(self, input_root: str | Path):
        self.input_root = Path(input_root)

    @staticmethod
    def _is_access_log(path: Path) -> bool:
        name = path.name.lower()
        return path.is_file() and name.startswith("access") and name.endswith(".log")

    @staticmethod
    def _sanitize_folder_name(path: Path) -> str:
        return path.stem.replace(".", "_")

    @staticmethod
    def _server_type_of(log_path: Path, scan_root: Path) -> str:
        try:
            relative = log_path.relative_to(scan_root)
        except ValueError:
            return "unknown"

        for part in relative.parts[:-1]:
            if part.lower() in SERVER_TYPE_FOLDERS:
                return part

        if scan_root.name.lower() in SERVER_TYPE_FOLDERS:
            return scan_root.name

        return "unknown"

    def _discover(self) -> tuple[Path, List[Path]]:
        if not self.input_root.exists():
            raise FileNotFoundError(
                f"Input path not found: {self.input_root}. "
                "Please put logs under input/ (e.g. input/Apache/access1.log)."
            )

        if self.input_root.is_file():
            scan_root = self.input_root.parent
            candidates = [self.input_root] if self._is_access_log(self.input_root) else []
        else:
            scan_root = self.input_root
            candidates = [
                p
                for p in sorted(self.input_root.rglob("access*.log"))
                if p.is_file()
            ]

        return scan_root, candidates

    def collect(self, output_root: str | Path) -> List[AccessLogJob]:
        scan_root, candidates = self._discover()

        output_root_path = Path(output_root)
        output_root_path.mkdir(parents=True, exist_ok=True)

        jobs: List[AccessLogJob] = []
        for log_path in candidates:
            server_type = self._server_type_of(log_path, scan_root)
            access_name = self._sanitize_folder_name(log_path)

            target_dir = output_root_path / server_type / access_name
            target_dir.mkdir(parents=True, exist_ok=True)

            target_txt = target_dir / f"{access_name}.txt"
            warning_file = target_dir / "log.txt"

            warnings: List[str] = []
            had_decode_warning = False

            try:
                with log_path.open("rb") as src, target_txt.open("wb") as dst:
                    for chunk in iter(lambda: src.read(1024 * 1024), b""):
                        dst.write(chunk)

                # Re-read by physical line to avoid chunk-boundary false negatives.
                with log_path.open("rb") as src_verify:
                    for raw_line in src_verify:
                        try:
                            raw_line.decode("utf-8", errors="strict")
                        except UnicodeDecodeError:
                            had_decode_warning = True
                            break
                if had_decode_warning:
                    warnings.append(
                        "WARNING: Non-UTF-8 byte sequences detected; "
                        "pipeline decode falls back to latin-1 for "
                        "downstream safety (raw .txt stays byte-exact)."
                    )
            except OSError as exc:
                warnings.append(f"ERROR: Failed to read/write file: {exc!r}")

            if warnings:
                timestamp = datetime.now(timezone.utc).isoformat()
                with warning_file.open("a", encoding="utf-8") as wf:
                    for warning in warnings:
                        wf.write(f"[{timestamp}] {warning}\n")

            jobs.append(
                AccessLogJob(
                    input_log_path=log_path,
                    server_type=server_type,
                    output_dir=target_dir,
                    output_txt_path=target_txt,
                )
            )

        return jobs
