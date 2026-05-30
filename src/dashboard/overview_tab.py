from __future__ import annotations

from typing import Any, Dict, List

import streamlit as st

try:
    import pandas as pd
except Exception:  # pragma: no cover - optional dependency
    pd = None

try:
    import plotly.express as px
except Exception:  # pragma: no cover - optional dependency
    px = None

from src.dashboard.components import render_empty_state, render_metric_card, safe_dataframe


EMPTY_MESSAGE = (
    "No security events found. Run the pipeline or enable DASHBOARD_USE_MOCK=1 for demo mode."
)


def _as_dataframe(records: List[Dict[str, Any]]):
    if pd is None:
        return records
    return pd.DataFrame(records)


def render_overview_tab(query_engine) -> None:
    st.markdown("## SOC Overview")
    st.caption("Real-time attack analytics powered by MongoDB Aggregation Pipeline")
    st.info("MongoDB Aggregation Pipeline turns raw events into attack intelligence.")

    summary = query_engine.get_soc_summary()

    total_requests = int(summary.get("total_requests", 0) or 0)
    malicious_requests = int(summary.get("malicious_requests", 0) or 0)
    total_incidents = int(summary.get("total_incidents", 0) or 0)
    active_campaigns = int(summary.get("active_campaigns", 0) or 0)
    high_severity = int(summary.get("high_severity_incidents", 0) or 0)

    if total_requests == 0 and not query_engine.is_mock_mode():
        render_empty_state("No Data", EMPTY_MESSAGE)
        return

    metric_cols = st.columns(5)
    with metric_cols[0]:
        render_metric_card("Total Requests", f"{total_requests:,}")
    with metric_cols[1]:
        render_metric_card("Malicious Requests", f"{malicious_requests:,}")
    with metric_cols[2]:
        render_metric_card("Total Incidents", f"{total_incidents:,}")
    with metric_cols[3]:
        render_metric_card("Active Campaigns", f"{active_campaigns:,}")
    with metric_cols[4]:
        render_metric_card("High Severity Incidents", f"{high_severity:,}")

    st.markdown("### Attack Type Distribution")
    distribution = query_engine.get_attack_type_distribution()
    if distribution:
        if px is not None and pd is not None:
            frame = pd.DataFrame(distribution)
            chart = px.pie(
                frame,
                values="count",
                names="attack_type",
                hole=0.55,
                color_discrete_sequence=["#38BDF8", "#22C55E", "#F59E0B", "#EF4444", "#8B5CF6"],
            )
            chart.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=10, r=10, t=30, b=10),
            )
            st.plotly_chart(chart, use_container_width=True)
        else:
            st.bar_chart({row["attack_type"]: row["count"] for row in distribution})
    else:
        render_empty_state("No Distribution Data", "No malicious request distribution is available yet.")

    top_ip_col, timeline_col = st.columns(2)

    with top_ip_col:
        st.markdown("### Top Attacking IPs")
        top_ips = query_engine.get_top_attacking_ips(limit=10)
        if top_ips:
            rows = []
            for row in top_ips:
                rows.append(
                    {
                        "ip": row.get("ip", "Unknown"),
                        "total_attacks": row.get("total_attacks", 0),
                        "attack_types": ", ".join(row.get("attack_types", [])),
                        "first_seen": row.get("first_seen", ""),
                        "last_seen": row.get("last_seen", ""),
                        "target_count": row.get("target_count", 0),
                    }
                )
            safe_dataframe(rows)
        else:
            render_empty_state("No Attacker IP Data", "No suspicious source IPs have been observed.")

    with timeline_col:
        st.markdown("### Attack Timeline")
        timeline = query_engine.get_attack_timeline()
        if timeline:
            if px is not None and pd is not None:
                frame = pd.DataFrame(timeline)
                frame = frame.sort_values("timestamp")
                chart = px.line(
                    frame,
                    x="timestamp",
                    y="count",
                    markers=True,
                    color_discrete_sequence=["#38BDF8"],
                )
                chart.update_layout(
                    template="plotly_dark",
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    margin=dict(l=10, r=10, t=30, b=10),
                    xaxis_title="Time",
                    yaxis_title="Malicious Events",
                )
                st.plotly_chart(chart, use_container_width=True)
            else:
                st.line_chart({row["timestamp"]: row["count"] for row in timeline})
        else:
            render_empty_state("Timeline Unavailable", "No valid timestamps found for malicious activity timeline.")

    st.markdown("### Active Campaigns")
    campaigns = query_engine.get_active_campaigns(min_attacks=10)
    if campaigns:
        rows = []
        for row in campaigns:
            rows.append(
                {
                    "ip": row.get("ip", "Unknown"),
                    "total_attacks": row.get("total_attacks", 0),
                    "attack_types": ", ".join(row.get("attack_types", [])),
                    "target_uris": ", ".join((row.get("target_uris") or [])[:4]),
                    "first_seen": row.get("first_seen", ""),
                    "last_seen": row.get("last_seen", ""),
                    "risk_level": row.get("risk_level", "unknown"),
                }
            )
        safe_dataframe(rows)
    else:
        render_empty_state("No Campaigns", "No active campaign pattern has been identified yet.")
