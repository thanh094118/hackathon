import csv
from datetime import datetime, timezone
import sys
from pathlib import Path
from queue import Queue
import tempfile
import time
import pytest

# Add scripts directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from simulate_stream import Producer, shutdown_event

def test_producer_timestamp_override():
    # Reset shutdown event in case it was set by other tests
    shutdown_event.clear()

    # Create a temporary CSV file with a 2020 timestamp
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, newline="", encoding="utf-8") as tf:
        writer = csv.writer(tf)
        writer.writerow(["timestamp", "src_ip", "request_http_method", "request_http_request"])
        writer.writerow(["17/Jul/2020:12:23:34 +0100", "172.26.0.1", "GET", "/"])
        tf_path = Path(tf.name)

    try:
        q = Queue()
        # Create a Producer that reads this CSV once at a high rate (e.g. 100 rows/sec)
        producer = Producer(
            queue=q,
            csv_path=tf_path,
            rate=100.0,
            loop=False,
            offset=0
        )
        
        producer.start()
        
        # Wait up to 2 seconds for producer to finish or queue to populate
        start_time = time.time()
        while q.empty() and time.time() - start_time < 2.0:
            time.sleep(0.1)

        # Get the row from queue
        assert not q.empty(), "Queue should not be empty"
        row = q.get()
        
        # Verify the timestamp has been updated to the current time, not 2020
        row_timestamp_str = row.get("timestamp")
        assert row_timestamp_str is not None
        assert "2020" not in row_timestamp_str
        
        # Try parsing it with the expected format
        try:
            parsed = datetime.strptime(row_timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
            # Ensure it is close to the current UTC time
            diff = abs((datetime.now(timezone.utc) - parsed).total_seconds())
            assert diff < 10.0, f"Timestamp difference too large: {diff} seconds"
        except ValueError as e:
            pytest.fail(f"Failed to parse timestamp string '{row_timestamp_str}': {e}")
            
    finally:
        shutdown_event.set()
        if tf_path.exists():
            tf_path.unlink()
