from __future__ import annotations

import logging
from typing import Any

from .models import CorrelatedIncident, TriageResult

log = logging.getLogger("fp_suppression")


class FPSuppressionEngine:
    """Uses Vector Search to match new incidents against a database of known false positives."""

    FP_COLLECTION = "false_positives"
    INCIDENTS_COLLECTION = "managed_incidents"

    def __init__(self, db: Any = None, similarity_threshold: float = 0.90) -> None:
        self.db = db
        self.similarity_threshold = similarity_threshold

    def _get_collection(self, name: str) -> Any:
        if self.db is not None:
            try:
                return self.db[name]
            except Exception:
                pass
        return None

    def triage(self, incident: CorrelatedIncident) -> TriageResult:
        """
        Calculates similarity with known false positives in MongoDB.
        If similarity exceeds the threshold, flags it as a false positive.
        """
        # Extract embedding from events in the correlated incident
        embedding = self._extract_embedding(incident)
        if not embedding:
            return TriageResult(is_false_positive=False, reason="No embedding vector available for triage")

        coll = self._get_collection(self.FP_COLLECTION)
        if coll is None:
            return TriageResult(is_false_positive=False, reason="False positives collection not available")

        try:
            from src.scoring.mongodb_queries import find_similar_false_positives
            results = find_similar_false_positives(
                collection=coll,
                query_vector=embedding,
                limit=1,
                index_name="vector_index"
            )
            if results:
                match = results[0]
                similarity = match.get("score", 0.0)
                if similarity >= self.similarity_threshold:
                    notes = match.get("notes") or "matched known false positive pattern"
                    return TriageResult(
                        is_false_positive=True,
                        similarity_score=similarity,
                        reason=f"Similarity {similarity:.3f} >= {self.similarity_threshold} with FP ({notes})",
                    )

        except Exception as e:
            # Fallback/Log on errors (like missing index during migrations or tests)
            log.warning(f"Vector search failed during triage: {e}")

        return TriageResult(is_false_positive=False, reason="No matching false positive pattern found")

    def mark_false_positive(self, incident_id: str, analyst_notes: str = "") -> bool:
        """
        Saves an incident's embedding and details as a known false positive.
        """
        coll_inc = self._get_collection(self.INCIDENTS_COLLECTION)
        coll_fp = self._get_collection(self.FP_COLLECTION)

        if coll_inc is None or coll_fp is None:
            log.error("MongoDB collections not available to mark false positive")
            return False

        try:
            # Try to fetch from managed_incidents
            inc = coll_inc.find_one({"_id": incident_id})
            if not inc:
                # Try fallback to incidents collection
                coll_fallback = self._get_collection("incidents")
                if coll_fallback is not None:
                    inc = coll_fallback.find_one({"_id": incident_id}) or coll_fallback.find_one({"event_id": incident_id})

            if not inc:
                log.error(f"Incident {incident_id} not found in database")
                return False

            # Extract embedding from incident or its first evidence event
            embedding = inc.get("embedding")
            if not embedding and inc.get("evidence"):
                for ev in inc["evidence"]:
                    if ev.get("embedding"):
                        embedding = ev["embedding"]
                        break

            if not embedding:
                log.error(f"Cannot mark incident {incident_id} as false positive: no embedding vector found")
                return False

            # Insert into false_positives collection
            import datetime
            doc = {
                "incident_id": incident_id,
                "notes": analyst_notes,
                "embedding": embedding,
                "created_at": datetime.datetime.now(datetime.timezone.utc),
                "title": inc.get("title") or inc.get("message") or "False Positive",
                "attack_type": inc.get("behavior_type") or inc.get("attack_type") or "unknown",
            }
            coll_fp.update_one({"incident_id": incident_id}, {"$set": doc}, upsert=True)

            # Update incident status in managed_incidents if exists
            coll_inc.update_one(
                {"_id": incident_id},
                {"$set": {"status": "resolved", "resolution": "false_positive", "resolution_notes": analyst_notes}},
            )
            return True

        except Exception as e:
            log.exception(f"Error marking incident {incident_id} as false positive")
            return False

    def _extract_embedding(self, incident: CorrelatedIncident) -> list[float] | None:
        # Check if the incident itself or any of its events contain an embedding vector
        if hasattr(incident, "events") and incident.events:
            for ev in incident.events:
                emb = ev.get("embedding")
                if emb and isinstance(emb, list) and all(isinstance(x, (int, float)) for x in emb):
                    return [float(x) for x in emb]

        # Check metadata/extra dict if any
        for ev in incident.events:
            # Deep check under ML prediction/features
            for val in (ev.get("detection", {}).get("ml", {}), ev.get("scoring", {})):
                if isinstance(val, dict) and val.get("embedding"):
                    emb = val["embedding"]
                    if isinstance(emb, list):
                        return [float(x) for x in emb]

        return None
