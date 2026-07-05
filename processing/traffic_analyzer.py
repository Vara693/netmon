# =============================================================================
# processing/traffic_analyzer.py — Traffic Analysis & Metric Aggregation
# =============================================================================
# Consumes packets from the queue, computes real-time metrics, and writes
# aggregated summaries to MongoDB every ANALYSIS_INTERVAL seconds.
#
# Metrics computed each interval:
#   • Total packets and bytes
#   • Bandwidth (Mbps)
#   • Packets per second (pps)
#   • Protocol distribution (%)
#   • Top talkers (by packet count and byte volume)
#   • Active connections (src_ip:src_port → dst_ip:dst_port)

import queue
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, List, Optional

import config
from utils.logger import get_logger

logger = get_logger(__name__)


class TrafficAnalyzer:
    """
    Drains the packet queue, aggregates metrics per time window, then:
      1. Passes summaries to DatabaseHandler for persistence.
      2. Emits per-window stats to the AlertDetector.
      3. Exposes latest metrics via get_realtime_stats() for the API.

    Args:
        packet_queue:  Shared queue populated by PacketCaptureEngine.
        db_handler:    DatabaseHandler instance (injected dependency).
        alert_engine:  AnomalyDetector instance (injected dependency).
    """

    def __init__(self, packet_queue: queue.Queue, db_handler=None, alert_engine=None):
        self.packet_queue = packet_queue
        self.db           = db_handler
        self.alerter      = alert_engine

        self._stop_event  = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock        = threading.Lock()

        # ── Per-interval accumulators (reset each flush) ──────────────────────
        self._reset_accumulators()

        # ── Rolling stats exposed to the API ─────────────────────────────────
        # Protected by _lock; safe to read from the API thread.
        self._realtime: Dict = {
            "packets_per_second": 0,
            "bandwidth_mbps":     0.0,
            "total_packets":      0,
            "total_bytes":        0,
            "active_connections": 0,
            "protocol_dist":      {},
            "top_talkers":        [],
            "timestamp":          datetime.now(timezone.utc).isoformat(),
        }

        # ── All-time counters (never reset) ───────────────────────────────────
        self._all_time_packets = 0
        self._all_time_bytes   = 0

        # ── Historical bandwidth ring-buffer for Z-score anomaly ──────────────
        # Stores the last N per-second bandwidth samples.
        self._bw_history: deque = deque(maxlen=120)   # ~2 minutes at 1-s intervals

    # ─── Public API ───────────────────────────────────────────────────────────

    def start(self) -> None:
        """Launch the analyzer thread."""
        logger.info("TrafficAnalyzer starting (interval=%ds)", config.ANALYSIS_INTERVAL)
        self._thread = threading.Thread(
            target=self._analysis_loop, daemon=True, name="AnalyzerThread"
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the analyzer to stop."""
        logger.info("TrafficAnalyzer stopping…")
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)

    def get_realtime_stats(self) -> Dict:
        """Thread-safe snapshot of the latest computed metrics."""
        with self._lock:
            return dict(self._realtime)

    def get_bw_history(self) -> List[float]:
        """Return the rolling bandwidth history (Mbps per interval)."""
        return list(self._bw_history)

    # ─── Internal Loop ────────────────────────────────────────────────────────

    def _analysis_loop(self) -> None:
        """
        Runs every ANALYSIS_INTERVAL seconds:
          1. Drain the packet queue into accumulators.
          2. Compute metrics from accumulators.
          3. Flush to DB.
          4. Run alert detection.
          5. Reset accumulators.
        """
        while not self._stop_event.is_set():
            # Sleep for the interval, waking early only if stop is set.
            self._stop_event.wait(timeout=config.ANALYSIS_INTERVAL)

            self._drain_queue()
            stats = self._compute_stats()
            self._update_realtime(stats)

            if self.db:
                self._flush_to_db(stats)
            if self.alerter:
                self.alerter.evaluate(stats)

            self._reset_accumulators()

    def _drain_queue(self) -> None:
        """Pull all available packets from the queue without blocking."""
        drained = 0
        while True:
            try:
                pkt = self.packet_queue.get_nowait()
                self._accumulate(pkt)
                drained += 1
            except queue.Empty:
                break
        logger.debug("Drained %d packets from queue", drained)

    def _accumulate(self, pkt: Dict) -> None:
        """Add a single packet's fields to the current interval accumulators."""
        self._interval_packets += 1
        self._interval_bytes   += pkt.get("size", 0)
        self._all_time_packets += 1
        self._all_time_bytes   += pkt.get("size", 0)

        proto = pkt.get("protocol", "OTHER")
        self._protocol_counts[proto] += 1

        src_ip = pkt.get("src_ip") or "unknown"
        self._ip_packet_counts[src_ip] += 1
        self._ip_byte_counts[src_ip]   += pkt.get("size", 0)

        dst_port = pkt.get("dst_port")
        if dst_port:
            self._port_counts_per_ip[src_ip].add(dst_port)

        # Track active connections as a frozenset so A→B and B→A collapse.
        src_port = pkt.get("src_port")
        dst_ip   = pkt.get("dst_ip") or "unknown"
        if src_port and dst_port:
            conn = (src_ip, src_port, dst_ip, dst_port, proto)
            self._active_connections.add(conn)

    # ─── Metrics Computation ──────────────────────────────────────────────────

    def _compute_stats(self) -> Dict:
        """Turn the raw accumulators into a clean metrics dict."""
        interval = config.ANALYSIS_INTERVAL
        pps      = self._interval_packets / interval
        bw_mbps  = (self._interval_bytes * 8) / (interval * 1_000_000)

        # Protocol distribution as percentages
        total_pkts = max(self._interval_packets, 1)
        proto_dist = {
            proto: round((count / total_pkts) * 100, 1)
            for proto, count in self._protocol_counts.items()
        }

        # Top 10 talkers sorted by packet count
        top_talkers = sorted(
            [
                {
                    "ip":         ip,
                    "packets":    pkts,
                    "bytes":      self._ip_byte_counts[ip],
                    "percentage": round((pkts / total_pkts) * 100, 1),
                }
                for ip, pkts in self._ip_packet_counts.items()
            ],
            key=lambda x: x["packets"],
            reverse=True,
        )[:10]

        # Serialize active connections to list-of-dicts
        connections = [
            {
                "src_ip":   c[0],
                "src_port": c[1],
                "dst_ip":   c[2],
                "dst_port": c[3],
                "protocol": c[4],
            }
            for c in list(self._active_connections)[:50]  # cap at 50
        ]

        # Per-IP distinct port counts (for port-scan detection)
        port_scan_candidates = {
            ip: len(ports)
            for ip, ports in self._port_counts_per_ip.items()
            if len(ports) >= config.ALERT_PORT_SCAN_THRESHOLD
        }

        stats = {
            "timestamp":           datetime.now(timezone.utc).isoformat(),
            "interval_seconds":    interval,
            "packets_per_second":  round(pps, 2),
            "bandwidth_mbps":      round(bw_mbps, 4),
            "interval_packets":    self._interval_packets,
            "interval_bytes":      self._interval_bytes,
            "total_packets":       self._all_time_packets,
            "total_bytes":         self._all_time_bytes,
            "protocol_dist":       proto_dist,
            "top_talkers":         top_talkers,
            "active_connections":  connections,
            "active_conn_count":   len(self._active_connections),
            "ip_packet_counts":    dict(self._ip_packet_counts),
            "port_scan_candidates": port_scan_candidates,
        }

        self._bw_history.append(bw_mbps)
        stats["bw_history"] = list(self._bw_history)

        return stats

    def _update_realtime(self, stats: Dict) -> None:
        with self._lock:
            self._realtime = {
                "packets_per_second": stats["packets_per_second"],
                "bandwidth_mbps":     stats["bandwidth_mbps"],
                "total_packets":      stats["total_packets"],
                "total_bytes":        stats["total_bytes"],
                "active_connections": stats["active_conn_count"],
                "protocol_dist":      stats["protocol_dist"],
                "top_talkers":        stats["top_talkers"],
                "timestamp":          stats["timestamp"],
            }

    def _flush_to_db(self, stats: Dict) -> None:
        """Persist the current interval stats to MongoDB."""
        try:
            # Exclude the full connection list from stats (stored separately)
            doc = {k: v for k, v in stats.items() if k != "active_connections"}
            self.db.insert_traffic_stat(doc)

            # Upsert active connections
            self.db.update_connections(stats["active_connections"])
        except Exception as exc:  # noqa: BLE001
            logger.error("DB flush error: %s", exc)

    # ─── Accumulator Reset ────────────────────────────────────────────────────

    def _reset_accumulators(self) -> None:
        self._interval_packets: int = 0
        self._interval_bytes:   int = 0
        self._protocol_counts:  Dict[str, int] = defaultdict(int)
        self._ip_packet_counts: Dict[str, int] = defaultdict(int)
        self._ip_byte_counts:   Dict[str, int] = defaultdict(int)
        self._active_connections: set = set()
        self._port_counts_per_ip: Dict[str, set] = defaultdict(set)
