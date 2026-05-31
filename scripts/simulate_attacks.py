from __future__ import annotations

import argparse
import random
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

NORMAL_PATHS = ["/", "/home", "/products", "/about", "/contact", "/assets/app.js"]
ATTACKS = {
    "sqli": ("/product", {"id": "1 UNION SELECT username,password FROM users--"}),
    "xss": ("/search", {"q": "<script>alert(1)</script>"}),
    "traversal": ("/image", {"name": "../../../../etc/passwd"}),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate simulated access logs (apache/nginx/iis).")
    parser.add_argument("--server-type", choices=["apache", "nginx", "iis"], default="apache")
    parser.add_argument("--total-requests", type=int, default=100)
    parser.add_argument("--output-file", default="data/input/access.log")
    parser.add_argument("--seed", type=int, default=42)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    total = max(1, int(args.total_requests))
    random.seed(args.seed)

    output_path = Path(args.output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines = generate_log_lines(server_type=args.server_type, total_requests=total)
    with output_path.open("w", encoding="utf-8") as f:
        if args.server_type == "iis":
            f.write("#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status cs(User-Agent)\n")
        for line in lines:
            f.write(line + "\n")

    print(f"Generated {len(lines)} lines -> {output_path}")
    return 0


def generate_log_lines(*, server_type: str, total_requests: int) -> list[str]:
    attack_count = max(1, round(total_requests * (10 / 110)))
    normal_count = total_requests - attack_count

    events: list[tuple[str, str, dict[str, str], int, str]] = []
    for _ in range(normal_count):
        path = random.choice(NORMAL_PATHS)
        events.append(("normal", path, {}, 200, "Mozilla/5.0"))
    attack_keys = ["sqli", "xss", "traversal"]
    for idx in range(attack_count):
        key = attack_keys[idx % len(attack_keys)]
        path, query = ATTACKS[key]
        events.append((key, path, query, random.choice([200, 403, 404]), f"attack-simulator-{key}/1.0"))

    random.shuffle(events)
    return [format_line(server_type, ev_type, path, query, status, ua) for ev_type, path, query, status, ua in events]


def format_line(server_type: str, ev_type: str, path: str, query: dict[str, str], status: int, user_agent: str) -> str:
    now = datetime.now(timezone.utc)
    query_string = urlencode(query, doseq=True)
    uri = path if not query_string else f"{path}?{query_string}"
    ip = "127.0.0.1"
    if server_type in {"apache", "nginx"}:
        ts = now.strftime("%d/%b/%Y:%H:%M:%S %z")
        return f'{ip} - - [{ts}] "GET {uri} HTTP/1.1" {status} 123 "-" "{user_agent}"'
    # iis
    date = now.strftime("%Y-%m-%d")
    tm = now.strftime("%H:%M:%S")
    uri_query = query_string if query_string else "-"
    return f"{date} {tm} {ip} GET {path} {uri_query} {status} {user_agent}"


if __name__ == "__main__":
    raise SystemExit(main())
