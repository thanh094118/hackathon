import os
from pymongo import MongoClient
import certifi

from src.dashboard.query_adapter import DashboardQueryAdapter, _normalize_request_record
from src.dashboard.investigator_tab import _matches_filter

from dotenv import load_dotenv
load_dotenv()

adapter = DashboardQueryAdapter()
incidents = adapter.get_recent_incidents(10)
print(f"Found {len(incidents)} incidents from adapter")
for row in incidents:
    has_rules = bool(row.get("matched_rule_ids") or row.get("rule_score", 0) > 0)
    has_ml = bool(row.get("ml_label") == "attack" or row.get("ml_should_alert"))
    print(f"- ML label: {row.get('ml_label')}, ML alert: {row.get('ml_should_alert')} -> has_ml: {has_ml}")
    print(f"  Rules: {row.get('matched_rule_ids')}, Score: {row.get('rule_score')} -> has_rules: {has_rules}")
    print(f"  Matches 'ML Only': {_matches_filter(row, 'ML Only')}")
