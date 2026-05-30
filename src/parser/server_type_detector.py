from __future__ import annotations

from typing import Iterable, List

from src.parser.apache_parser import ApacheParser
from src.parser.nginx_parser import NginxParser


def detect_server_type(lines: Iterable[str], *, sample_size: int = 200) -> str:
    """
    Detect server type from raw log content.

    Rules:
    - IIS if W3C headers are present (#Fields or #Software)
    - Apache vs Nginx by parser success count on a small sample
    - Default to Apache when uncertain or empty input
    """
    if sample_size <= 0:
        sample_size = 200

    sample: List[str] = []
    for line in lines:
        text = str(line)
        if not text.strip():
            continue

        stripped = text.lstrip()
        if stripped.startswith("#Fields:") or stripped.startswith("#Software:"):
            return "iis"

        sample.append(text)
        if len(sample) >= sample_size:
            break

    if not sample:
        return "apache"

    apache_ok = sum(
        1
        for row in ApacheParser().parse_lines(sample)
        if row.get("parse_status") == "success"
    )
    nginx_ok = sum(
        1
        for row in NginxParser().parse_lines(sample)
        if row.get("parse_status") == "success"
    )
    if nginx_ok > apache_ok:
        return "nginx"
    return "apache"
