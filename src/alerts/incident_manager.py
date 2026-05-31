from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any

from .models import CorrelatedIncident, IncidentAction

log = logging.getLogger("incident_mgr")


SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _get_severity_weight(severity: str | None) -> int:
    if not severity:
        return 0
    return SEVERITY_ORDER.get(str(severity).strip().lower(), 0)


class IncidentManager:
    """Manages stateful incident lifecycles (OPEN -> COOLDOWN -> CLOSED) in MongoDB or memory."""

    COLLECTION_NAME = "managed_incidents"

    def __init__(self, db: Any = None, cooldown_minutes: int = 30) -> None:
        self.db = db
        self.cooldown_minutes = cooldown_minutes
        self._in_memory_store: dict[str, dict[str, Any]] = {}  # Fallback for testing/no-db

    def _get_collection(self) -> Any:
        if self.db is not None:
            try:
                return self.db[self.COLLECTION_NAME]
            except Exception:
                pass
        return None

    def process_correlated_incident(self, incident: CorrelatedIncident) -> IncidentAction:
        """
        Processes a correlated incident:
        - Finds existing active incident in cooldown.
        - Checks for Severity Override (Escalation): if incoming event has higher severity, breaks cooldown.
        - Merges evidence if active incident exists.
        - Otherwise, creates a new incident, marks it as alert candidate, and puts it in cooldown.
        """
        now = datetime.now(timezone.utc)
        coll = self._get_collection()

        # Find active incident (status in open/cooldown and overlap in source_ips)
        active_incident = self._find_active_incident(incident, now)

        if active_incident:
            inc_id = active_incident["_id"]
            incoming_severity = incident.severity
            existing_severity = active_incident.get("severity")

            incoming_weight = _get_severity_weight(incoming_severity)
            existing_weight = _get_severity_weight(existing_severity)

            if incoming_weight > existing_weight:
                # Severity override / escalation! Merge evidence and override severity, returning NEW_ALERT
                self._merge_evidence(inc_id, incident, now, new_severity=incoming_severity)
                return IncidentAction(
                    action="NEW_ALERT",
                    incident_id=str(inc_id),
                    reason=f"Severity Escalation ({existing_severity} -> {incoming_severity}) during cooldown. Overriding.",
                )

            self._merge_evidence(inc_id, incident, now)
            return IncidentAction(
                action="MERGED",
                incident_id=str(inc_id),
                reason=f"Merged into active incident {inc_id} during cooldown",
            )
        else:
            new_id = self._create_new_incident(incident, now)
            return IncidentAction(
                action="NEW_ALERT",
                incident_id=new_id,
                reason="Created new incident, triggered notifications, and entered cooldown",
            )

    def _find_active_incident(self, incident: CorrelatedIncident, now: datetime) -> dict[str, Any] | None:
        coll = self._get_collection()
        ips = incident.source_ips

        if coll is not None:
            try:
                # Query Mongo: status in ("open", "cooldown") AND overlap in source_ips AND cooldown_until > now
                query = {
                    "status": {"$in": ["open", "cooldown"]},
                    "cooldown_until": {"$gt": now},
                    "source_ips": {"$in": ips},
                }
                doc = coll.find_one(query)
                if doc:
                    return doc
            except Exception as e:
                log.error(f"Error querying active incidents in MongoDB: {e}")
        else:
            # Memory query
            for inc_id, doc in self._in_memory_store.items():
                if doc["status"] in ("open", "cooldown"):
                    cooldown_until = doc["cooldown_until"]
                    if isinstance(cooldown_until, str):
                        cooldown_until = datetime.fromisoformat(cooldown_until)
                    if cooldown_until > now:
                        overlap = set(doc["source_ips"]) & set(ips)
                        if overlap:
                            doc["_id"] = inc_id
                            return doc
        return None

    def _merge_evidence(self, inc_id: Any, incident: CorrelatedIncident, now: datetime, new_severity: str | None = None) -> None:
        coll = self._get_collection()
        cooldown_until = now + timedelta(minutes=self.cooldown_minutes)

        if coll is not None:
            try:
                # Retrieve the existing incident to update fields locally or perform atomic updates
                existing = coll.find_one({"_id": inc_id})
                if not existing:
                    return

                new_attack_types = list(set(existing.get("attack_types", []) + incident.attack_types))
                new_endpoints = list(set(existing.get("target_endpoints", []) + incident.target_endpoints))
                new_evidence_ids = list(set(existing.get("evidence_ids", []) + incident.evidence_ids))
                max_risk = max(float(existing.get("max_risk_score", 0)), incident.max_risk_score)

                # Append events to evidence log, capped at 100 to avoid document bloat
                evidence = existing.get("evidence", [])
                for ev in incident.events:
                    if ev not in evidence:
                        evidence.append(ev)
                evidence = evidence[-100:]

                from src.alerts.correlation_engine import calculate_priority_risk_score
                max_risk = calculate_priority_risk_score(evidence)

                if max_risk >= 90:
                    resolved_severity = "critical"
                elif max_risk >= 70:
                    resolved_severity = "high"
                elif max_risk >= 40:
                    resolved_severity = "medium"
                else:
                    resolved_severity = "low"

                incoming_weight = SEVERITY_ORDER.get(new_severity or "", 0)
                resolved_weight = SEVERITY_ORDER.get(resolved_severity, 0)
                final_severity = resolved_severity if resolved_weight >= incoming_weight else new_severity

                update_fields = {
                    "attack_types": new_attack_types,
                    "target_endpoints": new_endpoints,
                    "evidence_ids": new_evidence_ids,
                    "max_risk_score": max_risk,
                    "evidence": evidence,
                    "evidence_count": len(new_evidence_ids),
                    "updated_at": now,
                    "cooldown_until": cooldown_until,  # Reset cooldown window
                    "severity": final_severity,
                }

                coll.update_one(
                    {"_id": inc_id},
                    {"$set": update_fields},
                )
            except Exception as e:
                log.error(f"Error merging evidence in MongoDB: {e}")
        else:
            doc = self._in_memory_store[str(inc_id)]
            new_attack_types = list(set(doc.get("attack_types", []) + incident.attack_types))
            new_endpoints = list(set(doc.get("target_endpoints", []) + incident.target_endpoints))
            new_evidence_ids = list(set(doc.get("evidence_ids", []) + incident.evidence_ids))

            evidence = doc.get("evidence", [])
            for ev in incident.events:
                if ev not in evidence:
                    evidence.append(ev)
            evidence = evidence[-100:]

            from src.alerts.correlation_engine import calculate_priority_risk_score
            max_risk = calculate_priority_risk_score(evidence)

            if max_risk >= 90:
                resolved_severity = "critical"
            elif max_risk >= 70:
                resolved_severity = "high"
            elif max_risk >= 40:
                resolved_severity = "medium"
            else:
                resolved_severity = "low"

            incoming_weight = SEVERITY_ORDER.get(new_severity or "", 0)
            resolved_weight = SEVERITY_ORDER.get(resolved_severity, 0)
            final_severity = resolved_severity if resolved_weight >= incoming_weight else new_severity

            update_data = {
                "attack_types": new_attack_types,
                "target_endpoints": new_endpoints,
                "evidence_ids": new_evidence_ids,
                "max_risk_score": max_risk,
                "evidence": evidence,
                "evidence_count": len(new_evidence_ids),
                "updated_at": now.isoformat(),
                "cooldown_until": cooldown_until.isoformat(),
                "severity": final_severity,
            }

            doc.update(update_data)

    def _create_new_incident(self, incident: CorrelatedIncident, now: datetime) -> str:
        coll = self._get_collection()
        cooldown_until = now + timedelta(minutes=self.cooldown_minutes)

        # Truncate evidence list to keep it neat
        evidence = incident.events[-100:]

        doc_data = {
            "status": "cooldown",
            "cooldown_until": cooldown_until if coll is not None else cooldown_until.isoformat(),
            "correlation_id": incident.correlation_id,
            "title": incident.title,
            "behavior_type": incident.behavior_type,
            "source_ips": incident.source_ips,
            "target_endpoints": incident.target_endpoints,
            "attack_types": incident.attack_types,
            "evidence_count": incident.evidence_count,
            "evidence_ids": incident.evidence_ids,
            "evidence": evidence,
            "max_risk_score": incident.max_risk_score,
            "severity": incident.severity,
            "created_at": now if coll is not None else now.isoformat(),
            "updated_at": now if coll is not None else now.isoformat(),
            "alert_sent": True,
        }

        if coll is not None:
            try:
                # Generate custom human-readable ID or standard UUID
                import uuid
                new_id = f"INC-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
                doc_data["_id"] = new_id
                coll.insert_one(doc_data)
                return new_id
            except Exception as e:
                log.error(f"Error inserting incident to MongoDB: {e}")
                # Fallback to in-memory on error
                pass

        # In-memory save
        import uuid
        new_id = f"INC-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        self._in_memory_store[new_id] = doc_data
        return new_id
