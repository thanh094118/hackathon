from __future__ import annotations

from typing import Any, Dict, List, Optional

import streamlit as st

try:
    import pandas as pd
except Exception:  # pragma: no cover - optional dependency
    pd = None

from src.dashboard.components import (
    render_empty_state,
    render_pattern_card,
    render_recommendation_list,
    safe_dataframe,
)


def _incident_label(row: Dict[str, Any]) -> str:
    return (
        f"{row.get('timestamp', '')} | {row.get('ip', 'Unknown')} | "
        f"{row.get('attack_type', 'Unknown')} | {str(row.get('uri', ''))[:60]}"
    )


def _table_rows(incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for row in incidents:
        out.append(
            {
                "incident_id": row.get("incident_id") or row.get("event_id") or "",
                "timestamp": row.get("timestamp", ""),
                "ip": row.get("ip", "Unknown"),
                "method": row.get("method", "-"),
                "uri": row.get("uri", "-"),
                "attack_type": row.get("attack_type", "Unknown"),
                "risk_score": row.get("risk_score", 0),
                "prediction_score": row.get("prediction_score", 0.0),
                "severity": row.get("severity", "unknown"),
            }
        )
    return out


def _pick_incident_id(incidents: List[Dict[str, Any]]) -> Optional[str]:
    if not incidents:
        return None

    table_rows = _table_rows(incidents)
    selected_id: Optional[str] = None

    st.markdown("### Incident Explorer")

    if pd is not None:
        frame = pd.DataFrame(table_rows)
        display = frame[[
            "timestamp",
            "ip",
            "method",
            "uri",
            "attack_type",
            "risk_score",
            "prediction_score",
            "severity",
        ]]

        try:
            event = st.dataframe(
                display,
                width="stretch",
                hide_index=True,
                on_select="rerun",
                selection_mode="single-row",
                key="incident_explorer_table",
            )
            selected_rows = []
            if event is not None:
                selection = getattr(event, "selection", None)
                if selection is not None:
                    selected_rows = list(getattr(selection, "rows", []) or [])
                elif isinstance(event, dict):
                    selected_rows = list(event.get("selection", {}).get("rows", []) or [])

            if selected_rows:
                idx = int(selected_rows[0])
                if 0 <= idx < len(table_rows):
                    selected_id = str(table_rows[idx].get("incident_id", "")).strip() or None
        except TypeError:
            # Streamlit version might not support dataframe row selection.
            safe_dataframe(display.to_dict(orient="records"))
        except Exception:
            safe_dataframe(display.to_dict(orient="records"))
    else:
        safe_dataframe(table_rows)

    if not selected_id:
        selected_index = st.selectbox(
            "Select an incident",
            options=list(range(len(incidents))),
            format_func=lambda idx: _incident_label(incidents[idx]),
        )
        selected_id = str(incidents[int(selected_index)].get("incident_id") or incidents[int(selected_index)].get("event_id") or "")

    return selected_id


def render_investigator_tab(query_engine) -> None:
    st.markdown("## Threat Investigator")
    st.caption("Investigate hybrid-scored suspicious requests with MongoDB Vector Search")
    st.info("MongoDB Vector Search explains suspicious requests by matching hybrid risk evidence to known attack patterns.")

    incidents = query_engine.get_recent_incidents(limit=100)
    if not incidents:
        render_empty_state(
            "No Incidents",
            "No suspicious or malicious incidents are available right now.",
        )
        return

    selected_id = _pick_incident_id(incidents)
    if not selected_id:
        st.warning("Please select an incident to continue investigation.")
        return

    detail = query_engine.get_incident_detail(selected_id)
    if detail is None:
        # Fallback to the list item itself if detail lookup misses due to schema mismatch.
        for row in incidents:
            row_id = str(row.get("incident_id") or row.get("event_id") or "")
            if row_id == str(selected_id):
                detail = row
                break

    if detail is None:
        st.warning("Selected incident details are not available.")
        return

    st.markdown("### Incident Detail")

    verdict = str(detail.get("verdict") or "unknown").lower()
    confidence = float(detail.get("prediction_score", 0.0) or 0.0)
    risk_score = int(float(detail.get("risk_score", 0) or 0))

    summary_cols = st.columns(4)
    summary_cols[0].metric("Verdict", verdict)
    summary_cols[1].metric("Confidence", f"{round(confidence * 100, 1)}%")
    summary_cols[2].metric("Risk Score", f"{risk_score}")
    summary_cols[3].metric("Attack Type", str(detail.get("attack_type") or "Unknown"))

    left_col, right_col = st.columns(2)
    with left_col:
        st.markdown(f"- **Event ID:** `{detail.get('event_id', '')}`")
        st.markdown(f"- **Incident ID:** `{detail.get('incident_id', '')}`")
        st.markdown(f"- **Source IP:** `{detail.get('ip', 'Unknown')}`")
        st.markdown(f"- **Method:** `{detail.get('method', '-')}`")
        st.markdown(f"- **URI:** `{detail.get('uri', '-')}`")
    with right_col:
        st.markdown(f"- **Severity:** `{detail.get('severity', 'unknown')}`")
        st.markdown(f"- **Timestamp:** `{detail.get('timestamp', '')}`")
        st.markdown(f"- **User-Agent:** `{detail.get('user_agent', '')}`")
        matched_ids = detail.get("matched_rule_ids") or []
        if isinstance(matched_ids, list) and matched_ids:
            st.markdown(f"- **Matched Rules:** `{', '.join(str(x) for x in matched_ids[:8])}`")

    normalized_request = str(detail.get("normalized_request") or "").strip()
    if normalized_request:
        with st.expander("Normalized Request", expanded=False):
            st.code(normalized_request, language="text")

    raw_payload = str(detail.get("raw") or "").strip()
    if raw_payload:
        st.markdown("#### Raw Payload")
        st.code(raw_payload, language="text")

    st.markdown("### Vector Search Explanation")
    embedding = detail.get("embedding") or []
    patterns: List[Dict[str, Any]] = []

    if isinstance(embedding, list) and embedding:
        patterns = query_engine.find_similar_attack_patterns(embedding, limit=3)

    if patterns:
        top = patterns[0]
        score = float(top.get("score", 0.0) or 0.0)
        score_percent = round(score * 100, 1) if score <= 1.0 else round(score, 2)
        st.success(
            f"Top Match: {top.get('name', 'Unknown')} | Similarity: {score_percent}% | MITRE: {top.get('mitre', 'N/A')}"
        )
        for pattern in patterns:
            render_pattern_card(pattern)
    else:
        st.warning(
            "Vector Search is not available yet. Showing rule-based explanation or mock pattern recommendations."
        )

    # ── Semantic Similar Logs ──────────────────────────────────────────────────
    with st.expander("🔍 Semantic Similar Logs", expanded=False):
        st.markdown(
            "Find historically similar attack payloads using MongoDB Vector Search — "
            "even when syntax is obfuscated or completely different."
        )

        has_embedding = isinstance(embedding, list) and len(embedding) > 0
        if not has_embedding:
            st.warning(
                "⚠️ No embedding vector is available for this incident. "
                "Semantic search requires the request to have been processed by the embedding engine."
            )
        else:
            if st.button("🔍 Find Similar Incidents in History", key="btn_find_similar_incidents"):
                with st.spinner("Searching for semantically similar incidents…"):
                    similar_logs: List[Dict[str, Any]] = []
                    try:
                        similar_logs = query_engine.find_similar_requests(embedding, limit=5)
                    except Exception as exc:
                        st.error(f"Search failed: {exc}")

                if similar_logs:
                    similar_rows = []
                    for item in similar_logs:
                        sim_score = float(item.get("similarity_score", 0.0) or 0.0)
                        similar_rows.append(
                            {
                                "Timestamp": item.get("timestamp", ""),
                                "Source IP": item.get("ip", "Unknown"),
                                "URI": str(item.get("uri", "-"))[:80],
                                "Risk Score": item.get("risk_score", 0),
                                "Semantic Match": f"{round(sim_score * 100, 1)}%",
                            }
                        )
                    st.success(f"Found **{len(similar_rows)}** semantically similar incident(s).")
                    safe_dataframe(similar_rows)
                else:
                    st.info(
                        "No semantically similar incidents found in the database. "
                        "This may be the first time this payload pattern has been observed."
                    )
    # ── End Semantic Similar Logs ──────────────────────────────────────────────

    st.markdown("### Hybrid Risk Explanation")
    st.write(query_engine.build_rule_based_explanation(detail))

    st.markdown("### Recommended Response")
    recommendations = query_engine.get_response_recommendations(detail, patterns=patterns)
    render_recommendation_list(recommendations)

