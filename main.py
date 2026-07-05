import os
import queue
import signal
import sys
import threading
import time

import click

# ─── Ensure project root is in path ──────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from utils.logger import get_logger

logger = get_logger("main")


@click.command()
@click.option("--simulate",  is_flag=True,  default=False,
              help="Generate synthetic traffic (no root required)")
@click.option("--api-only",  is_flag=True,  default=False,
              help="Start API and dashboard only (no packet capture)")
@click.option("--interface", default=None,  metavar="IFACE",
              help="Network interface to capture on (overrides config.py)")
@click.option("--port",      default=config.FLASK_PORT, type=int,
              help=f"Port for the web dashboard (default: {config.FLASK_PORT})")
def main(simulate: bool, api_only: bool, interface: str, port: int):
    """
    NetMon — Real-Time Network Monitoring & Traffic Analysis System
    """
    logger.info("=" * 60)
    logger.info("  NetMon Starting Up")
    logger.info("  Mode      : %s",
                "API-ONLY" if api_only else ("SIMULATE" if simulate else "LIVE CAPTURE"))
    logger.info("  Interface : %s", interface or config.NETWORK_INTERFACE)
    logger.info("  Dashboard : http://localhost:%d", port)
    logger.info("=" * 60)

    # ── 1. Packet Queue ───────────────────────────────────────────────────────
    packet_queue: queue.Queue = queue.Queue(maxsize=config.PACKET_QUEUE_MAX)

    # ── 2. Database ───────────────────────────────────────────────────────────
    from database.db_handler import DatabaseHandler
    db = DatabaseHandler()
    db_ok = db.connect()
    if not db_ok:
        logger.warning("Running without persistent storage (MongoDB unavailable)")

    # ── 3. Anomaly Detector ───────────────────────────────────────────────────
    from alerts.anomaly_detector import AnomalyDetector
    alerter = AnomalyDetector(db_handler=db if db_ok else None)

    # ── 4. Traffic Analyzer ───────────────────────────────────────────────────
    from processing.traffic_analyzer import TrafficAnalyzer
    analyzer = TrafficAnalyzer(
        packet_queue=packet_queue,
        db_handler=db if db_ok else None,
        alert_engine=alerter,
    )

    # ── 5. Packet Capture Engine ──────────────────────────────────────────────
    capture_engine = None
    if not api_only:
        from capture.packet_capture import PacketCaptureEngine
        capture_engine = PacketCaptureEngine(
            packet_queue=packet_queue,
            interface=interface or config.NETWORK_INTERFACE,
            simulate=simulate,
        )

    # ── 6. Flask App ──────────────────────────────────────────────────────────
    from api.routes import create_app
    app = create_app(analyzer=analyzer, db=db, alerter=alerter)

    # ── 7. Graceful Shutdown ──────────────────────────────────────────────────
    def shutdown(signum, frame):
        logger.info("Shutdown signal received — stopping all threads…")
        if capture_engine:
            capture_engine.stop()
        analyzer.stop()
        db.disconnect()
        logger.info("NetMon stopped. Goodbye.")
        sys.exit(0)

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # ── 8. Start Threads ──────────────────────────────────────────────────────
    if capture_engine:
        capture_engine.start()
    analyzer.start()

    logger.info("All services started. Open http://localhost:%d in your browser.", port)
    logger.info("Login: %s / %s", config.DASHBOARD_USERNAME, config.DASHBOARD_PASSWORD)

    # ── 9. Start Flask (blocking — main thread) ────────────────────────────────
    app.run(
        host=config.FLASK_HOST,
        port=port,
        debug=False,
        use_reloader=False,
        threaded=True,
    )


if __name__ == "__main__":
    main()
