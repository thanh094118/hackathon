from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from .models import BaselineResult

log = logging.getLogger("dynamic_baseline")


def get_endpoint_group(uri: str | None) -> str:
    """Categorizes a request URI into a group to apply customized baselines."""
    if not uri:
        return "root"
    uri_lower = uri.strip().lower()
    path = uri_lower.split("?")[0].strip()
    if any(k in path for k in ["backup", "db", "admin", "config", "settings"]):
        return "sensitive"
    
    parts = [p for p in path.split("/") if p]
    if not parts:
        return "root"
    if parts[0] == "api" and len(parts) >= 2:
        return f"api_{parts[1]}"
    return parts[0]


IN_MEMORY_FLOORS = {
    "sensitive": 2,
    "api": 20,
    "root": 100,
}

IN_MEMORY_BASELINES = {
    "sensitive": (0.5, 0.2),
    "default": (5.0, 2.0),
}


class DynamicBaseline:
    """Calculates and checks attack counts against a moving baseline and standard deviation."""

    BASELINE_COLLECTION = "attack_baselines"
    REQUESTS_COLLECTION = "requests"
    MIN_FLOORS_COLLECTION = "endpoint_min_floors"

    def __init__(self, db: Any = None, sigma_multiplier: float = 3.0, lookback_weeks: int = 4, min_floor: int = 50) -> None:
        self.db = db
        self.sigma_multiplier = sigma_multiplier
        self.lookback_weeks = lookback_weeks
        self.min_floor = min_floor

    def _get_collection(self, name: str) -> Any:
        if self.db is not None:
            try:
                return self.db[name]
            except Exception:
                pass
        return None

    def get_hour_of_week(self, dt: datetime) -> int:
        """Returns hour of week: 0 to 167 (0 = Mon 00:00, 167 = Sun 23:00)."""
        dt_utc = dt.astimezone(timezone.utc)
        return dt_utc.weekday() * 24 + dt_utc.hour

    def get_min_floor_for_group(self, endpoint_group: str) -> int:
        """Resolves the minimum floor for a specific endpoint group."""
        coll_floors = self._get_collection(self.MIN_FLOORS_COLLECTION)
        
        # If in DB, use it
        if coll_floors is not None:
            try:
                floor_doc = coll_floors.find_one({"_id": endpoint_group})
                if floor_doc:
                    return int(floor_doc.get("min_floor"))
            except Exception:
                pass
        
        # Fallback to IN_MEMORY_FLOORS or self.min_floor
        return IN_MEMORY_FLOORS.get(endpoint_group, self.min_floor)

    def should_alert_above_baseline(self, current_hour_count: int, dt: datetime | None = None, endpoint_group: str = "default") -> BaselineResult:
        """
        Checks if current count is greater than baseline mean + N * std_dev and >= group-specific min_floor.
        """
        if dt is None:
            dt = datetime.now(timezone.utc)

        hour_of_week = self.get_hour_of_week(dt)
        coll_baseline = self._get_collection(self.BASELINE_COLLECTION)

        # Resolve min floor
        group_min_floor = self.get_min_floor_for_group(endpoint_group)

        # Resolve mean & std_dev
        mean, std_dev = IN_MEMORY_BASELINES.get(endpoint_group, IN_MEMORY_BASELINES["default"])
        if coll_baseline is not None:
            try:
                # Try grouping by compound key first
                doc = coll_baseline.find_one({"_id": {"hour_of_week": hour_of_week, "endpoint_group": endpoint_group}})
                if not doc:
                    # Fallback to legacy single key doc
                    doc = coll_baseline.find_one({"_id": hour_of_week})
                
                if doc:
                    mean = float(doc.get("mean", mean))
                    std_dev = float(doc.get("std_dev", std_dev))
            except Exception as e:
                log.error(f"Error loading baseline for hour {hour_of_week} group {endpoint_group}: {e}")

        # Ensure std_dev is positive to prevent division by zero or negative bounds
        std_dev = max(0.1, std_dev)
        threshold = mean + self.sigma_multiplier * std_dev
        
        # Must be above dynamic threshold AND at or above minimum hard floor
        should_alert = (current_hour_count > threshold) and (current_hour_count >= group_min_floor)

        deviation_ratio = 0.0
        if current_hour_count > mean:
            deviation_ratio = (current_hour_count - mean) / std_dev

        return BaselineResult(
            should_alert=should_alert,
            current_count=current_hour_count,
            baseline_mean=mean,
            baseline_std=std_dev,
            threshold=threshold,
            hour_of_week=hour_of_week,
            deviation_ratio=deviation_ratio,
        )

    def calculate_baselines(self) -> dict[str, Any]:
        """
        Runs aggregation over requests to calculate baseline statistics for each hour of the week
        and stores/merges them into the attack_baselines collection.
        """
        from src.scoring.mongodb_queries import calculate_attack_baselines
        return calculate_attack_baselines(
            db=self.db,
            requests_collection=self.REQUESTS_COLLECTION,
            baseline_collection=self.BASELINE_COLLECTION
        )

    def calculate_min_floors(self, percentile: float = 0.90, scale_factor: float = 0.10) -> dict[str, Any]:
        """Runs aggregation over requests to calculate endpoint-group specific min floors."""
        from src.scoring.mongodb_queries import calculate_endpoint_min_floors
        return calculate_endpoint_min_floors(
            db=self.db,
            requests_collection=self.REQUESTS_COLLECTION,
            min_floors_collection=self.MIN_FLOORS_COLLECTION,
            percentile=percentile,
            scale_factor=scale_factor
        )

