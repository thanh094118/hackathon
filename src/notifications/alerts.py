from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Mapping

from src.alerts import AlertEvent, AlertSendResult, build_default_dispatcher
from src.alerts.models import CorrelatedIncident, IncidentAction, BatchAlertResult
from src.alerts.correlation_engine import CorrelationEngine
from src.alerts.incident_manager import IncidentManager
from src.alerts.dynamic_baseline import DynamicBaseline
from src.alerts.fp_suppression import FPSuppressionEngine

log = logging.getLogger("notifications_alerts")

HIGH_SEVERITIES = {"high", "critical"}


def should_alert_incident(incident: Mapping[str, Any], threshold: int = 80) -> bool:
    risk_score = _risk_score(incident)
    if risk_score is not None and risk_score >= float(threshold):
        return True

    severity = _first(incident, "severity", "risk_level", "rule_severity")
    if severity is not None and str(severity).strip().lower() in HIGH_SEVERITIES:
        return True

    return False


def send_incident_alert(
    incident: Mapping[str, Any],
    threshold: int = 80,
    dispatcher: Any | None = None,
) -> list[AlertSendResult]:
    """
    Stateless fallback / backward-compatible method for sending an alert.
    If the incident should be alerted, wraps it and sends via dispatcher.
    """
    if not should_alert_incident(incident, threshold=threshold):
        return []

    try:
        resolved_dispatcher = dispatcher or build_default_dispatcher()
        alert = AlertEvent.from_incident(incident)
        return list(resolved_dispatcher.send(alert))
    except Exception as exc:
        return [
            AlertSendResult(
                channel="alerts",
                success=False,
                message="incident alert failed",
                dry_run=False,
                error=exc.__class__.__name__,
            )
        ]


def process_batch_alerts(
    alerts: list[dict[str, Any]],
    db: Any = None,
    dispatcher: Any | None = None,
    window_minutes: int = 5,
    cooldown_minutes: int = 30,
    threshold: int = 80,
    fp_similarity_threshold: float = 0.90,
    sigma_multiplier: float = 3.0,
    min_floor: int = 50,
) -> BatchAlertResult:
    """
    Stateful batch alerting pipeline:
    1. Group alerts into CorrelatedIncidents
    2. Check dynamic anomaly baseline
    3. Check vector similarity with known false positives
    4. Check cooldown & incident lifecycle
    5. Dispatch notifications for new alerts
    """
    if not alerts:
        return BatchAlertResult(0, 0, 0, 0, 0, [])

    # Step 1: Correlate alerts
    correlator = CorrelationEngine(window_minutes=window_minutes)
    correlated_incidents = correlator.correlate_alerts(alerts)

    actions: list[IncidentAction] = []
    alert_sent_count = 0
    merged_count = 0
    suppressed_count = 0

    # Instantiate engines
    baseline_engine = DynamicBaseline(db, sigma_multiplier=sigma_multiplier, min_floor=min_floor)
    triage_engine = FPSuppressionEngine(db, similarity_threshold=fp_similarity_threshold)
    incident_mgr = IncidentManager(db, cooldown_minutes=cooldown_minutes)

    # Determine current count of alerts per endpoint group for baseline calculation
    now = datetime.now(timezone.utc)
    from src.alerts.dynamic_baseline import get_endpoint_group

    # Count alerts in the current batch per endpoint group
    batch_group_counts = {}
    for alert in alerts:
        uri = alert.get("uri") or alert.get("request", {}).get("uri")
        grp = get_endpoint_group(uri)
        batch_group_counts[grp] = batch_group_counts.get(grp, 0) + 1

    # Fetch DB counts in the last hour per endpoint group
    db_group_counts = {}
    if db is not None:
        try:
            one_hour_ago = now - timedelta(hours=1)
            coll_req = db[DynamicBaseline.REQUESTS_COLLECTION]
            pipeline = [
                {
                    "$match": {
                        "$and": [
                            {
                                "$or": [
                                    {"timestamp": {"$type": "date", "$gte": one_hour_ago}},
                                    {"timestamp": {"$type": "string", "$gte": one_hour_ago.isoformat()}},
                                ]
                            },
                            {
                                "$or": [
                                    {"scoring.should_alert": True},
                                    {"scoring.final_label": {"$in": ["malicious", "suspicious"]}},
                                ]
                            }
                        ]
                    }
                },
                {
                    "$project": {
                        "uri_val": {"$ifNull": ["$request.uri", "$uri"]}
                    }
                },
                {
                    "$addFields": {
                        "endpoint_group": {
                            "$cond": {
                                "if": { "$regexMatch": { "input": {"$ifNull": ["$uri_val", ""]}, "regex": "backup|db|admin|config|settings", "options": "i" } },
                                "then": "sensitive",
                                "else": {
                                    "$let": {
                                        "vars": {
                                            "parts": { "$split": [{"$ifNull": ["$uri_val", ""]}, "/"] }
                                        },
                                        "in": {
                                            "$cond": {
                                                "if": { "$gt": [{ "$size": "$$parts" }, 1] },
                                                "then": {
                                                    "$cond": {
                                                        "if": { "$eq": [{ "$arrayElemAt": ["$$parts", 1] }, "api"] },
                                                        "then": {
                                                            "$cond": {
                                                                "if": { "$gt": [{ "$size": "$$parts" }, 2] },
                                                                "then": { "$concat": ["api_", { "$arrayElemAt": ["$$parts", 2] }] },
                                                                "else": "api"
                                                            }
                                                        },
                                                        "else": { "$arrayElemAt": ["$$parts", 1] }
                                                    }
                                                },
                                                "else": "root"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                {
                    "$group": {
                        "_id": "$endpoint_group",
                        "count": {"$sum": 1}
                    }
                }
            ]
            for doc in coll_req.aggregate(pipeline):
                db_group_counts[doc["_id"]] = doc["count"]
        except Exception as e:
            log.warning(f"Failed to query endpoint group counts from requests collection: {e}")

    for inc in correlated_incidents:
        # Check stateless threshold first (only filter if maximum score in incident is below threshold)
        if inc.max_risk_score < threshold and inc.severity not in HIGH_SEVERITIES:
            # Below severity threshold, suppress
            actions.append(IncidentAction(
                action="SUPPRESSED",
                incident_id=inc.correlation_id,
                reason=f"Below severity threshold ({inc.max_risk_score} < {threshold})"
            ))
            suppressed_count += 1
            continue

        # Step 2: Dynamic Baseline check per endpoint group
        inc_groups = list(set(get_endpoint_group(ep) for ep in (inc.target_endpoints or [])))
        if not inc_groups:
            inc_groups = ["default"]

        allowed_groups = []
        suppressed_groups = []

        for grp in inc_groups:
            grp_count = max(batch_group_counts.get(grp, 0), db_group_counts.get(grp, 0))
            baseline_res = baseline_engine.should_alert_above_baseline(grp_count, inc.window_start, endpoint_group=grp)
            if baseline_res.should_alert:
                allowed_groups.append((grp, grp_count, baseline_res))
            else:
                suppressed_groups.append((grp, grp_count, baseline_res))

        if not allowed_groups:
            grp_details = ", ".join(
                f"{g}: count {c} <= threshold {res.threshold:.1f} (floor {baseline_engine.get_min_floor_for_group(g)})"
                for g, c, res in suppressed_groups
            )
            reason = f"Below dynamic anomaly baseline for target groups ({grp_details})"
            actions.append(IncidentAction(
                action="SUPPRESSED",
                incident_id=inc.correlation_id,
                reason=reason
            ))
            suppressed_count += 1
            _save_suppressed_incident(db, inc, "below_baseline", reason)
            continue

        # Step 3: False Positive Suppression check
        triage_res = triage_engine.triage(inc)
        if triage_res.is_false_positive:
            actions.append(IncidentAction(
                action="SUPPRESSED",
                incident_id=inc.correlation_id,
                reason=triage_res.reason
            ))
            suppressed_count += 1
            _save_suppressed_incident(db, inc, "false_positive", triage_res.reason or "Matched known false positive vector")
            continue

        # Step 4: Incident Lifecycle & Cooldown
        action = incident_mgr.process_correlated_incident(inc)
        actions.append(action)

        if action.action == "NEW_ALERT":
            # Dispatch alert
            try:
                resolved_dispatcher = dispatcher or build_default_dispatcher()
                # Create AlertEvent
                alert_event = AlertEvent(
                    incident_id=action.incident_id,
                    timestamp=inc.window_start.isoformat(),
                    severity=inc.severity,
                    attack_type=inc.behavior_type,
                    risk_score=inc.max_risk_score,
                    source_ip=inc.source_ips[0] if inc.source_ips else "Unknown",
                    uri=inc.target_endpoints[0] if inc.target_endpoints else "Multiple",
                    message=inc.title,
                    metadata={
                        "evidence_count": inc.evidence_count,
                        "evidence_ids": inc.evidence_ids,
                        "behavior_type": inc.behavior_type,
                        "target_endpoints": inc.target_endpoints,
                        "attack_types": inc.attack_types,
                    }
                )
                resolved_dispatcher.send(alert_event)
                alert_sent_count += 1
            except Exception as e:
                log.exception(f"Failed to dispatch stateful alert for incident {action.incident_id}: {e}")
        elif action.action == "MERGED":
            merged_count += 1

    return BatchAlertResult(
        processed_count=len(alerts),
        correlated_count=len(correlated_incidents),
        alert_sent_count=alert_sent_count,
        merged_count=merged_count,
        suppressed_count=suppressed_count,
        actions=actions
    )


def _save_suppressed_incident(db: Any, incident: CorrelatedIncident, resolution: str, notes: str) -> None:
    """Helper to save suppressed incidents to managed_incidents for UI transparency."""
    if db is None:
        return
    try:
        import uuid
        now = datetime.now(timezone.utc)
        coll = db[IncidentManager.COLLECTION_NAME]
        new_id = f"INC-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        doc_data = {
            "_id": new_id,
            "status": "resolved",
            "resolution": resolution,
            "resolution_notes": notes,
            "correlation_id": incident.correlation_id,
            "title": incident.title,
            "behavior_type": incident.behavior_type,
            "source_ips": incident.source_ips,
            "target_endpoints": incident.target_endpoints,
            "attack_types": incident.attack_types,
            "evidence_count": incident.evidence_count,
            "evidence_ids": incident.evidence_ids,
            "evidence": incident.events[-100:],
            "max_risk_score": incident.max_risk_score,
            "severity": incident.severity,
            "created_at": now,
            "updated_at": now,
            "alert_sent": False,
        }
        coll.insert_one(doc_data)
    except Exception as e:
        log.warning(f"Failed to save suppressed incident to database: {e}")


def _risk_score(incident: Mapping[str, Any]) -> float | None:
    value = _first(incident, "risk_score", "score", "final_score", "rule_score")
    if value is None:
        prediction = incident.get("prediction")
        if isinstance(prediction, Mapping):
            value = prediction.get("risk_score")

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _first(incident: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in incident and incident[key] not in (None, ""):
            return incident[key]
    return None
