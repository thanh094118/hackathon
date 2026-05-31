from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AttackPayload:
    attack_type: str
    display_name: str
    method: str
    uri: str
    raw_request: str
    risk_score: int
    severity: str
    prediction_score: float
    mitre: list[str]
    matched_pattern: str
    recommendations: list[str]


PAYLOADS: dict[str, AttackPayload] = {
    "sqli": AttackPayload(
        attack_type="SQLI",
        display_name="SQL Injection",
        method="GET",
        uri="/product?id=1 UNION SELECT username,password FROM users--",
        raw_request="GET /product?id=1 UNION SELECT username,password FROM users-- HTTP/1.1",
        risk_score=95,
        severity="high",
        prediction_score=0.96,
        mitre=["T1190"],
        matched_pattern="sqli_union_select",
        recommendations=[
            "Validate and parameterize database queries.",
            "Inspect database access logs for related activity.",
        ],
    ),
    "xss": AttackPayload(
        attack_type="XSS",
        display_name="Cross-Site Scripting",
        method="GET",
        uri="/search?q=<script>alert(1)</script>",
        raw_request="GET /search?q=<script>alert(1)</script> HTTP/1.1",
        risk_score=90,
        severity="high",
        prediction_score=0.94,
        mitre=["T1059"],
        matched_pattern="xss_script_tag",
        recommendations=[
            "Validate and encode user-controlled output.",
            "Review affected templates for unsafe rendering.",
        ],
    ),
    "traversal": AttackPayload(
        attack_type="TRAVERSAL",
        display_name="Directory Traversal",
        method="GET",
        uri="/image?name=../../../../etc/passwd",
        raw_request="GET /image?name=../../../../etc/passwd HTTP/1.1",
        risk_score=88,
        severity="high",
        prediction_score=0.92,
        mitre=["T1083"],
        matched_pattern="traversal_dotdot",
        recommendations=[
            "Normalize and validate file paths server-side.",
            "Restrict application filesystem access.",
        ],
    ),
}


def normalize_attack_type(attack_type: str) -> str:
    value = str(attack_type or "").strip().lower().replace("-", "_")
    aliases = {
        "sql": "sqli",
        "sql_injection": "sqli",
        "cross_site_scripting": "xss",
        "path_traversal": "traversal",
        "directory_traversal": "traversal",
    }
    return aliases.get(value, value)


def get_payload(attack_type: str) -> AttackPayload:
    normalized = normalize_attack_type(attack_type)
    if normalized not in PAYLOADS:
        supported = ", ".join(sorted(PAYLOADS))
        raise ValueError(f"Unsupported attack_type '{attack_type}'. Supported values: {supported}")
    return PAYLOADS[normalized]
