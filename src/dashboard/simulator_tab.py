from __future__ import annotations

import os
from dataclasses import asdict, is_dataclass
from typing import Any

import streamlit as st

from src.simulator.engine import simulate_attack


ATTACK_BUTTONS = [
    ("SQL Injection Scan", "sqli"),
    ("Cross-Site Scripting Probe", "xss"),
    ("Directory Traversal Attack", "traversal"),
]


def render_simulator_tab(query_engine: Any) -> None:
    st.markdown("## Attack Simulator")
    st.caption("Generate controlled demo attacks for dashboard validation")

    enabled = _env_bool("SIMULATOR_ENABLED", default=False)
    default_mode = os.getenv("SIMULATOR_MODE", "direct-mongo")
    max_count = max(1, _env_int("SIMULATOR_MAX_COUNT", 20))

    if enabled:
        st.success("Simulator is enabled for this environment.")
    else:
        st.warning("Simulator is disabled. Set SIMULATOR_ENABLED=1 to enable demo attack generation.")

    left_col, right_col = st.columns(2)
    with left_col:
        mode = st.selectbox(
            "Simulator mode",
            options=["direct-mongo", "target-url"],
            index=0 if default_mode != "target-url" else 1,
            disabled=not enabled,
        )
        count = int(
            st.number_input(
                "Count",
                min_value=1,
                max_value=max_count,
                value=1,
                step=1,
                disabled=not enabled,
            )
        )
    with right_col:
        target_url = st.text_input(
            "Target URL",
            value=os.getenv("SIMULATOR_DEFAULT_TARGET", "http://localhost:8080"),
            disabled=not enabled or mode != "target-url",
        )
        delay = float(
            st.number_input(
                "Delay between requests",
                min_value=0.0,
                max_value=10.0,
                value=0.0,
                step=0.5,
                disabled=not enabled,
            )
        )

    st.warning("Simulator payloads are for controlled local/demo environments only.")

    button_cols = st.columns(3)
    for index, (label, attack_type) in enumerate(ATTACK_BUTTONS):
        with button_cols[index]:
            if st.button(label, disabled=not enabled, width="stretch"):
                st.session_state["simulator_results"] = _run_simulation(
                    query_engine=query_engine,
                    mode=mode,
                    attack_type=attack_type,
                    count=count,
                    delay=delay,
                    target_url=target_url,
                )

    _render_results(st.session_state.get("simulator_results") or [])
    _render_mode_comparison()


def _run_simulation(
    *,
    query_engine: Any,
    mode: str,
    attack_type: str,
    count: int,
    delay: float,
    target_url: str,
):
    db = None
    if mode == "direct-mongo" and not query_engine.is_mock_mode():
        db = getattr(query_engine, "db", None)

    return simulate_attack(
        mode=mode,
        attack_type=attack_type,
        count=count,
        delay=delay,
        target_url=target_url,
        db=db,
        send_alerts=True,
    )


def _render_results(results: list[Any]) -> None:
    st.markdown("### Simulator Results")
    if not results:
        st.info("No simulator run has been executed in this session.")
        return

    rows = []
    for result in results:
        payload = asdict(result) if is_dataclass(result) else dict(result)
        alert_results = payload.get("alert_results") or []
        payload["alert_results"] = _format_alert_results(alert_results)
        rows.append(payload)

    st.dataframe(rows, width="stretch", hide_index=True)


def _format_alert_results(alert_results: list[Any]) -> str:
    if not alert_results:
        return ""
    values = []
    for result in alert_results:
        channel = getattr(result, "channel", None)
        success = getattr(result, "success", None)
        if channel is None and isinstance(result, dict):
            channel = result.get("channel")
            success = result.get("success")
        values.append(f"{channel or 'unknown'}:{'ok' if success else 'fail'}")
    return ", ".join(values)


def _render_mode_comparison() -> None:
    st.markdown("### Mode Comparison")
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown(
            """
**Direct Mongo Mode**
- stable
- writes synthetic events directly to MongoDB
- good for hackathon demo
- can trigger alert immediately
"""
        )
    with col_b:
        st.markdown(
            """
**Target URL Mode**
- more realistic
- sends HTTP requests to local/demo service
- requires collector/pipeline to be running
- may not instantly appear in MongoDB if pipeline is not active
"""
        )


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on", "y"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default
