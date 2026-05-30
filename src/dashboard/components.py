from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

import streamlit as st

try:
    import pandas as pd
except Exception:  # pragma: no cover - optional dependency
    pd = None


def render_metric_card(label: str, value: Any, delta: Optional[str] = None, help_text: Optional[str] = None) -> None:
    delta_text = f"<div class='tl-metric-delta'>{delta}</div>" if delta else ""
    help_html = f"<div class='tl-metric-help'>{help_text}</div>" if help_text else ""
    st.markdown(
        f"""
        <div class="tl-card tl-metric-card">
            <div class="tl-metric-label">{label}</div>
            <div class="tl-metric-value">{value}</div>
            {delta_text}
            {help_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_status_badge(label: str, status: str) -> None:
    status_key = str(status or "unknown").strip().lower().replace(" ", "-")
    st.markdown(
        f"""
        <div class="tl-status-row">
            <span class="tl-status-label">{label}</span>
            <span class="tl-status-badge tl-status-{status_key}">{status}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_severity_badge(severity: str) -> str:
    value = str(severity or "unknown").strip().lower()
    class_name = f"tl-severity tl-severity-{value}"
    return f"<span class='{class_name}'>{value}</span>"


def render_empty_state(title: str, message: str) -> None:
    st.markdown(
        f"""
        <div class="tl-card tl-empty-state">
            <div class="tl-empty-title">{title}</div>
            <div class="tl-empty-message">{message}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_pattern_card(pattern: Dict[str, Any]) -> None:
    name = pattern.get("name", "Unknown Pattern")
    attack_type = pattern.get("attack_type", "Unknown")
    score = float(pattern.get("score", 0.0) or 0.0)
    score_percent = round(score * 100, 1) if score <= 1.0 else round(score, 2)
    mitre = pattern.get("mitre", "N/A")
    severity = str(pattern.get("severity", "unknown"))
    description = pattern.get("description", "No description available")
    examples = pattern.get("examples") or []

    st.markdown(
        f"""
        <div class="tl-card tl-pattern-card">
            <div class="tl-pattern-title">{name}</div>
            <div class="tl-pattern-meta">
                <span>Type: {attack_type}</span>
                <span>Similarity: {score_percent}%</span>
                <span>MITRE: {mitre}</span>
                {render_severity_badge(severity)}
            </div>
            <div class="tl-pattern-desc">{description}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if examples:
        st.caption("Examples: " + " | ".join(str(item) for item in examples[:3]))


def render_recommendation_list(recommendations: Iterable[str]) -> None:
    items = [str(item).strip() for item in recommendations if str(item).strip()]
    if not items:
        return

    st.markdown("<div class='tl-recommendations-title'>Recommended Actions</div>", unsafe_allow_html=True)
    for item in items:
        st.markdown(f"- {item}")


def safe_dataframe(records: List[Dict[str, Any]], *, width: str = "stretch", hide_index: bool = True):
    if pd is not None:
        frame = pd.DataFrame(records)
        st.dataframe(frame, width=width, hide_index=hide_index)
        return frame

    st.dataframe(records, width=width, hide_index=hide_index)
    return records
