from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlencode


@dataclass(frozen=True)
class AttackPayload:
    key: str
    method: str
    path: str
    query: dict[str, str]
    user_agent: str

    def encoded_uri(self) -> str:
        query_string = urlencode(self.query, doseq=True)
        return f"{self.path}?{query_string}" if query_string else self.path


PAYLOADS: dict[str, AttackPayload] = {
    "normal": AttackPayload(
        key="normal",
        method="GET",
        path="/",
        query={},
        user_agent="traffic-simulator-normal/1.0",
    ),
    "sqli": AttackPayload(
        key="sqli",
        method="GET",
        path="/product",
        query={"id": "1 UNION SELECT username,password FROM users--"},
        user_agent="attack-simulator-sqli/1.0",
    ),
    "xss": AttackPayload(
        key="xss",
        method="GET",
        path="/search",
        query={"q": "<script>alert(1)</script>"},
        user_agent="attack-simulator-xss/1.0",
    ),
    "traversal": AttackPayload(
        key="traversal",
        method="GET",
        path="/image",
        query={"name": "../../../../etc/passwd"},
        user_agent="attack-simulator-traversal/1.0",
    ),
}


def normalize_attack_type(attack_type: str) -> str:
    value = str(attack_type or "").strip().lower().replace("-", "_")
    aliases = {
        "sql": "sqli",
        "sql_injection": "sqli",
        "cross_site_scripting": "xss",
        "directory_traversal": "traversal",
        "path_traversal": "traversal",
    }
    return aliases.get(value, value)


def get_payload(attack_type: str) -> AttackPayload:
    key = normalize_attack_type(attack_type)
    if key not in PAYLOADS:
        supported = ", ".join(sorted(PAYLOADS))
        raise ValueError(f"Unsupported attack type '{attack_type}'. Supported: {supported}")
    return PAYLOADS[key]


def cycle_attack_types(attack_type: str, count: int) -> list[str]:
    key = normalize_attack_type(attack_type)
    safe_count = max(1, int(count))
    if key != "all":
        return [key] * safe_count
    keys = [item for item in PAYLOADS if item != "normal"]
    return [keys[index % len(keys)] for index in range(safe_count)]
