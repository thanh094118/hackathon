from __future__ import annotations

import streamlit as st


def render_simulator_tab() -> None:
    st.markdown("## Simulator Guide")
    st.caption("Attack simulation is CLI-only. The dashboard does not trigger traffic.")
    st.code(
        "\n".join(
            [
                "# 1) Start your local web server (must write access logs)",
                "# Example target URL: http://127.0.0.1:8080",
                "",
                "# 2) Send simulated traffic",
                "SIMULATOR_ENABLED=1 SIMULATOR_DRY_RUN=0 python scripts/simulate_attacks.py --mode target-url --target-url http://localhost:8080 --attack-type all --count 3 --delay 1",
                "",
                "# 3) Run pipeline using the web server access log path",
                "python -m src.main --input /path/to/your/access.log --server-type apache --export mongodb",
            ]
        ),
        language="bash",
    )
