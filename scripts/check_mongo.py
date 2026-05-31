from src.dashboard.query_adapter import DashboardQueryAdapter

from dotenv import load_dotenv
load_dotenv()

adapter = DashboardQueryAdapter()
incidents = adapter.get_recent_incidents(10)
print(f"Found {len(incidents)} incidents from adapter")
for row in incidents:
    print(
        f"- {row.get('event_id')}: method={row.get('detection_method')}, "
        f"sources={row.get('detection_sources')}, "
        f"primary={row.get('primary_signal')}, risk={row.get('risk_score')}"
    )
