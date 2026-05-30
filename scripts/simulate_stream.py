"""
Stream Simulator — Producer-Consumer Architecture
===================================================
Producer: Reads rows from data/input/data_capec_multilabel.csv at a controlled
          rate and pushes them into a shared queue.
Consumer: Pipeline runs continuously as a consumer, pulling micro-batches from
          the queue, running full detection pipeline, and exporting to MongoDB.

Usage:
    # Continuous stream: producer feeds 10 rows/sec, consumer processes batches of 50
    python scripts/simulate_stream.py

    # Faster for demo
    python scripts/simulate_stream.py --batch-size 200 --rate 50

    # Single batch then exit
    python scripts/simulate_stream.py --once --batch-size 100

    # Loop CSV when exhausted
    python scripts/simulate_stream.py --loop --rate 20

    # Limit total batches
    python scripts/simulate_stream.py --max-batches 10
"""

from __future__ import annotations

import argparse
import csv
import logging
import os
import signal
import sys
import tempfile
import threading
import time
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Dict, List, Optional

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.converter.convert_flow import _normalize_keys, _to_raw_log_lines

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("stream_sim")

# ── Defaults ─────────────────────────────────────────────────────────────────
DEFAULT_CSV = PROJECT_ROOT / "data" / "input" / "data_capec_multilabel.csv"
DEFAULT_BATCH_SIZE = 50
DEFAULT_RATE = 10          # rows per second pushed by producer
DEFAULT_CONSUMER_WAIT = 3  # seconds consumer waits for a full batch before flushing partial
DEFAULT_RULES = PROJECT_ROOT / "src" / "rules" / "attack_patterns.yaml"
TEMP_DIR = PROJECT_ROOT / "data" / "raw" / "_stream_tmp"


# ── Shared state ─────────────────────────────────────────────────────────────
shutdown_event = threading.Event()


def _signal_handler(signum, frame):
    log.info("⛔ Shutdown signal received. Draining queue...")
    shutdown_event.set()


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# ═══════════════════════════════════════════════════════════════════════════════
#  PRODUCER — reads CSV rows → pushes to queue at controlled rate
# ═══════════════════════════════════════════════════════════════════════════════
class Producer(threading.Thread):
    """Reads CSV rows and pushes raw dicts into the shared queue."""

    def __init__(
        self,
        queue: Queue,
        csv_path: Path,
        rate: float,
        loop: bool = False,
        offset: int = 0,
    ):
        super().__init__(daemon=True, name="producer")
        self.queue = queue
        self.csv_path = csv_path
        self.rate = rate  # rows per second
        self.loop = loop
        self.offset = offset
        self.total_produced = 0

    def run(self):
        interval = 1.0 / self.rate if self.rate > 0 else 0
        while not shutdown_event.is_set():
            try:
                self._read_csv(interval)
            except Exception:
                log.exception("Producer error reading CSV")
                break
            if not self.loop:
                break
            log.info("🔄 CSV exhausted — looping back to start")

        log.info("📤 Producer finished. Total rows produced: %d", self.total_produced)

    def _read_csv(self, interval: float):
        with self.csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh)
            # Skip offset rows
            for _ in range(self.offset):
                try:
                    next(reader)
                except StopIteration:
                    return

            for row in reader:
                if shutdown_event.is_set():
                    return
                self.queue.put(row)
                self.total_produced += 1
                if self.total_produced % 500 == 0:
                    log.info("📤 Producer: %d rows pushed", self.total_produced)
                if interval > 0:
                    time.sleep(interval)


# ═══════════════════════════════════════════════════════════════════════════════
#  CONSUMER — pipeline always running, pulls batches from queue
# ═══════════════════════════════════════════════════════════════════════════════
class Consumer(threading.Thread):
    """
    Pipeline consumer that runs forever.
    Pulls rows from the queue, converts to log lines, writes a temp file,
    and runs the full detection pipeline on it.
    """

    def __init__(
        self,
        queue: Queue,
        batch_size: int,
        consumer_wait: float,
        rules_path: Path,
        mongodb_uri: Optional[str],
        ml_enable: bool,
        ml_model_dir: Optional[Path],
        ml_threshold: float,
        debug_local: bool,
        max_batches: int = 0,
    ):
        super().__init__(daemon=True, name="consumer")
        self.queue = queue
        self.batch_size = batch_size
        self.consumer_wait = consumer_wait
        self.rules_path = rules_path
        self.mongodb_uri = mongodb_uri
        self.ml_enable = ml_enable
        self.ml_model_dir = ml_model_dir
        self.ml_threshold = ml_threshold
        self.debug_local = debug_local
        self.max_batches = max_batches

        self.batch_count = 0
        self.total_consumed = 0
        self.total_alerts = 0

    def run(self):
        TEMP_DIR.mkdir(parents=True, exist_ok=True)
        log.info("🔁 Consumer started — waiting for data...")

        while not shutdown_event.is_set():
            # Pull a batch from queue
            batch = self._pull_batch()
            if not batch:
                # Queue is empty and producer is done
                if not self._producer_alive():
                    log.info("📭 Queue empty and producer finished. Consumer exiting.")
                    break
                continue

            # Process the batch through the pipeline
            self.batch_count += 1
            self.total_consumed += len(batch)
            log.info(
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            )
            log.info(
                "📥 Batch #%d — processing %d rows (total consumed: %d)",
                self.batch_count, len(batch), self.total_consumed,
            )

            try:
                summary = self._process_batch(batch)
                alerts = summary.get("counts", {}).get("alerts", 0)
                self.total_alerts += alerts
                log.info(
                    "✅ Batch #%d done — %d alerts (cumulative: %d alerts from %d rows)",
                    self.batch_count, alerts, self.total_alerts, self.total_consumed,
                )
            except Exception:
                log.exception("❌ Batch #%d failed", self.batch_count)

            # Check max batches limit
            if self.max_batches > 0 and self.batch_count >= self.max_batches:
                log.info("🛑 Reached max batches (%d). Stopping consumer.", self.max_batches)
                shutdown_event.set()
                break

        log.info(
            "📊 Consumer summary: %d batches, %d rows, %d alerts",
            self.batch_count, self.total_consumed, self.total_alerts,
        )

    def _producer_alive(self) -> bool:
        """Check if producer thread is still alive."""
        for t in threading.enumerate():
            if t.name == "producer" and t.is_alive():
                return True
        return False

    def _pull_batch(self) -> List[Dict[str, Any]]:
        """
        Pull up to batch_size rows from queue.
        Waits up to consumer_wait seconds for the batch to fill.
        Returns partial batch if timeout expires (so consumer stays responsive).
        """
        batch: List[Dict[str, Any]] = []
        deadline = time.time() + self.consumer_wait

        while len(batch) < self.batch_size:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                row = self.queue.get(timeout=min(remaining, 0.5))
                batch.append(row)
            except Empty:
                # If we have some rows and producer is gone, flush what we have
                if batch and not self._producer_alive():
                    break
                if shutdown_event.is_set():
                    break
                continue

        return batch

    def _process_batch(self, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Convert rows to log lines, write temp file, run pipeline."""
        # Convert CSV rows → Apache access log lines
        log_lines: List[str] = []
        for row in rows:
            normalized = _normalize_keys(row)
            for line in _to_raw_log_lines(normalized):
                text = str(line).strip()
                if text:
                    log_lines.append(text)

        if not log_lines:
            return {"counts": {"raw_lines": 0, "alerts": 0}}

        # Write temp file
        tmp_path = TEMP_DIR / f"batch_{self.batch_count:06d}.log"
        tmp_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")

        # Output dir for this batch (only used when debug_local=True)
        output_dir = TEMP_DIR / f"batch_{self.batch_count:06d}_out"

        try:
            # Import here to avoid circular imports at module load time
            from src.main import _run_single_pipeline

            summary = _run_single_pipeline(
                input_path=tmp_path,
                run_output_dir=output_dir,
                rules_path=self.rules_path,
                ml_enable=self.ml_enable,
                ml_model_dir=self.ml_model_dir,
                ml_threshold=self.ml_threshold,
                server_type="apache",
                mongodb_uri=self.mongodb_uri,
                debug_local=self.debug_local,
            )
            return summary
        finally:
            # Cleanup temp log file (keep output dir if debug_local)
            if tmp_path.exists() and not self.debug_local:
                tmp_path.unlink(missing_ok=True)


# ═══════════════════════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════════════════════
def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Stream Simulator — Producer reads CSV, Consumer runs pipeline continuously",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--csv", default=str(DEFAULT_CSV), help="Path to input CSV (default: data/input/data_capec_multilabel.csv)")
    p.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help=f"Rows per pipeline batch (default: {DEFAULT_BATCH_SIZE})")
    p.add_argument("--rate", type=float, default=DEFAULT_RATE, help=f"Producer rate: rows/sec pushed to queue (default: {DEFAULT_RATE})")
    p.add_argument("--consumer-wait", type=float, default=DEFAULT_CONSUMER_WAIT, help=f"Max seconds consumer waits for a full batch (default: {DEFAULT_CONSUMER_WAIT})")
    p.add_argument("--rules", default=str(DEFAULT_RULES), help="Rule YAML path")
    p.add_argument("--mongodb-uri", default=None, help="MongoDB URI (overrides MONGODB_URI env var)")
    p.add_argument("--ml-enable", action="store_true", default=True, help="Enable ML inference")
    p.add_argument("--ml-model-dir", default="models/ml", help="ML model directory")
    p.add_argument("--ml-threshold", type=float, default=0.5, help="ML threshold")
    p.add_argument("--debug-local", action="store_true", help="Keep local output files per batch")
    p.add_argument("--loop", action="store_true", help="Loop CSV from start when exhausted")
    p.add_argument("--offset", type=int, default=0, help="Skip N rows at start of CSV")
    p.add_argument("--max-batches", type=int, default=0, help="Stop after N batches (0 = unlimited)")
    p.add_argument("--once", action="store_true", help="Process one batch then exit")
    p.add_argument("--queue-size", type=int, default=5000, help="Max queue size (backpressure)")
    return p


def main():
    from dotenv import load_dotenv
    load_dotenv()

    args = build_cli().parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        log.error("CSV not found: %s", csv_path)
        sys.exit(1)

    mongodb_uri = args.mongodb_uri or os.getenv("MONGODB_URI")
    max_batches = 1 if args.once else args.max_batches

    # Shared queue with bounded size for backpressure
    queue: Queue = Queue(maxsize=args.queue_size)

    log.info("═══════════════════════════════════════════════════════")
    log.info("  🚀 Stream Simulator — Producer-Consumer Pipeline")
    log.info("═══════════════════════════════════════════════════════")
    log.info("  CSV:         %s", csv_path.name)
    log.info("  Batch size:  %d rows", args.batch_size)
    log.info("  Rate:        %.1f rows/sec", args.rate)
    log.info("  MongoDB:     %s", "✅ enabled" if mongodb_uri else "❌ disabled")
    log.info("  ML:          %s", "✅ enabled" if args.ml_enable else "❌ disabled")
    log.info("  Loop:        %s", "✅ yes" if args.loop else "❌ no")
    log.info("  Max batches: %s", max_batches if max_batches > 0 else "unlimited")
    log.info("═══════════════════════════════════════════════════════")

    # Start producer
    producer = Producer(
        queue=queue,
        csv_path=csv_path,
        rate=args.rate,
        loop=args.loop,
        offset=args.offset,
    )

    # Start consumer
    consumer = Consumer(
        queue=queue,
        batch_size=args.batch_size,
        consumer_wait=args.consumer_wait,
        rules_path=Path(args.rules),
        mongodb_uri=mongodb_uri,
        ml_enable=args.ml_enable,
        ml_model_dir=Path(args.ml_model_dir),
        ml_threshold=args.ml_threshold,
        debug_local=args.debug_local,
        max_batches=max_batches,
    )

    producer.start()
    consumer.start()

    # Main thread waits for consumer to finish
    try:
        while consumer.is_alive():
            consumer.join(timeout=1.0)
    except KeyboardInterrupt:
        shutdown_event.set()
        log.info("⛔ Interrupted — waiting for graceful shutdown...")
        consumer.join(timeout=10)

    log.info("👋 Stream simulator exited.")


if __name__ == "__main__":
    main()
