from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import streamlit as st

from src.dashboard.components import render_status_badge
from src.dashboard.investigator_tab import render_investigator_tab
from src.dashboard.overview_tab import render_overview_tab
from src.dashboard.query_adapter import DashboardQueryAdapter


def _page_title() -> str:
    value = str(os.getenv("DASHBOARD_PAGE_TITLE", "")).strip()
    return value or "ThreatLens AI"


def _load_styles() -> None:
    css_path = Path(__file__).with_name("styles.css")
    if not css_path.exists():
        return
    st.markdown(f"<style>{css_path.read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)


@st.cache_resource(show_spinner=False)
def _get_query_engine(refresh_nonce: int, use_mock_override: Optional[bool] = None) -> DashboardQueryAdapter:
    # refresh_nonce intentionally busts cache when user clicks refresh.
    return DashboardQueryAdapter(use_mock=use_mock_override)


def _rerun_app() -> None:
    rerun = getattr(st, "rerun", None)
    if callable(rerun):
        rerun()
        return

    experimental = getattr(st, "experimental_rerun", None)
    if callable(experimental):  # pragma: no cover - old Streamlit fallback
        experimental()


def _render_sidebar(query_engine: DashboardQueryAdapter) -> str:
    status = query_engine.status()

    with st.sidebar:
        st.markdown("<div class='tl-brand'>ThreatLens AI</div>", unsafe_allow_html=True)
        st.markdown("<div class='tl-tagline'>AI SOC Copilot powered by MongoDB</div>", unsafe_allow_html=True)
        st.markdown("---")

        render_status_badge("MongoDB Status", status.get("connection", "Unknown"))

        if status.get("message"):
            st.caption(str(status.get("message")))

        st.markdown("### Navigation")
        navigation = st.radio(
            "Choose workspace",
            options=["SOC Overview", "Threat Investigator"],
            label_visibility="collapsed",
        )

        st.markdown("### Runtime")
        st.caption(f"Database: {status.get('database_name', 'N/A')}")
        st.caption(f"Collections: {len(status.get('available_collections', []))}")
        st.caption(f"Last refresh: {status.get('last_refresh', '')}")

        if st.button("Refresh Data", width="stretch"):
            st.session_state["tl_refresh_nonce"] = st.session_state.get("tl_refresh_nonce", 0) + 1
            _rerun_app()

    return navigation


def main() -> None:
    st.set_page_config(
        page_title="ThreatLens AI",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    _load_styles()

    if "tl_refresh_nonce" not in st.session_state:
        st.session_state["tl_refresh_nonce"] = 0

    query_engine = _get_query_engine(st.session_state["tl_refresh_nonce"], None)

    st.markdown(f"# {_page_title()}")
    st.caption("AI SOC Copilot powered by MongoDB")

    navigation = _render_sidebar(query_engine)

    if navigation == "SOC Overview":
        render_overview_tab(query_engine)
    else:
        render_investigator_tab(query_engine)


if __name__ == "__main__":
    main()
