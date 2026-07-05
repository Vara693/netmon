# =============================================================================
# alerts/anomaly_detector.py — Rule-Based + Statistical Anomaly Detection
# =============================================================================
# Evaluates each traffic interval's metrics against:
#   1. Hard thresholds  (simple, explainable rules)
#   2. Z-score analysis (statistical deviation from historical baseline)
#
# When an anomaly is detected:
#   • The alert is logged to the console/file.
#   • The alert is persisted in MongoDB via DatabaseHandler.
#   • An in-memory ring buffer keeps the last N alerts for the API.

from collections import deque
from datetime import datetime, timezone
from typing import Dict, List, Optional

import numpy as np  # type: ignore

import config
from utils.logger import get_logger

logger = get_logger(__name__)


class AnomalyDetector:
    """
    Rule-based and statistical anomaly detection engine.

    Args:
        db_handler: DatabaseHandler instance for persisting alerts.
    """

    def __init__(self, db_handler=None):
        self.db = db_handler
        # In-memory alert buffer (newest first) — always available even without DB
        self._alert_buffer: deque = deque(maxlen=500)
        # Historical bandwidth samples for Z-score baseline
        self._bw_history: deque = deque(maxlen=config.ANOMALY_MIN_HISTORY * 5)

    # ─── Public API ───────────────────────────────────────────────────────────

    def evaluate(self, stats: Dict) -> List[Dict]:
        """
        Run all detection rules against a freshly computed stats interval.

        Args:
            stats: Dict produced by TrafficAnalyzer._compute_stats()

        Returns:
            List of alert dicts generated this interval (may be empty).
        """
        alerts_this_interval = []

        # Update bandwidth baseline
        self._bw_history.append(stats.get("bandwidth_mbps", 0))

        # ── Rule 1: Packets-per-second spike ─────────────────────────────────
        pps = stats.get("packets_per_second", 0)
        if pps > config.ALERT_PPS_THRESHOLD:
            alert = self._make_alert(
                alert_type="TRAFFIC_SPIKE",
                severity="HIGH",
                source_ip=None,
                message=(
                    f"Packet rate {pps:.0f} pps exceeds threshold "
                    f"{config.ALERT_PPS_THRESHOLD} pps — possible DoS"
                ),
                details={"packets_per_second": pps, "threshold": config.ALERT_PPS_THRESHOLD},
            )
            alerts_this_interval.append(alert)

        # ── Rule 2: Single-IP rate limit ─────────────────────────────────────
        ip_counts = stats.get("ip_packet_counts", {})
        for ip, count in ip_counts.items():
            if count > config.ALERT_IP_RATE_LIMIT:
                alert = self._make_alert(
                    alert_type="IP_RATE_LIMIT",
                    severity="MEDIUM",
                    source_ip=ip,
                    message=(
                        f"IP {ip} sent {count} packets in "
                        f"{config.ANALYSIS_INTERVAL}s "
                        f"(limit: {config.ALERT_IP_RATE_LIMIT})"
                    ),
                    details={"ip": ip, "count": count, "limit": config.ALERT_IP_RATE_LIMIT},
                )
                alerts_this_interval.append(alert)

        # ── Rule 3: Suspicious port access ───────────────────────────────────
        for conn in stats.get("active_connections", []):
            dst_port = conn.get("dst_port")
            src_ip   = conn.get("src_ip")
            if dst_port and dst_port in config.ALERT_SUSPICIOUS_PORTS:
                alert = self._make_alert(
                    alert_type="SUSPICIOUS_PORT",
                    severity="MEDIUM",
                    source_ip=src_ip,
                    message=(
                        f"Connection to suspicious port {dst_port} from {src_ip}"
                    ),
                    details={"src_ip": src_ip, "dst_port": dst_port, "protocol": conn.get("protocol")},
                )
                alerts_this_interval.append(alert)
                break  # One alert per interval is enough

        # ── Rule 4: Port scan detection ───────────────────────────────────────
        for ip, port_count in stats.get("port_scan_candidates", {}).items():
            alert = self._make_alert(
                alert_type="PORT_SCAN",
                severity="HIGH",
                source_ip=ip,
                message=(
                    f"Possible port scan: {ip} accessed {port_count} distinct ports "
                    f"in {config.ANALYSIS_INTERVAL}s"
                ),
                details={"ip": ip, "distinct_ports": port_count},
            )
            alerts_this_interval.append(alert)

        # ── Rule 5: Statistical Z-score anomaly ───────────────────────────────
        if len(self._bw_history) >= config.ANOMALY_MIN_HISTORY:
            history_arr = np.array(list(self._bw_history)[:-1])  # exclude current
            mean = float(np.mean(history_arr))
            std  = float(np.std(history_arr))
            current_bw = stats.get("bandwidth_mbps", 0)

            if std > 0:
                z_score = (current_bw - mean) / std
                if abs(z_score) > config.ANOMALY_ZSCORE_THRESHOLD:
                    direction = "spike" if z_score > 0 else "drop"
                    alert = self._make_alert(
                        alert_type="BANDWIDTH_ANOMALY",
                        severity="HIGH" if abs(z_score) > 5 else "MEDIUM",
                        source_ip=None,
                        message=(
                            f"Statistical bandwidth {direction}: {current_bw:.2f} Mbps "
                            f"(z-score={z_score:.1f}, mean={mean:.2f}, σ={std:.2f})"
                        ),
                        details={
                            "current_mbps": current_bw,
                            "mean_mbps":    round(mean, 4),
                            "std_mbps":     round(std, 4),
                            "z_score":      round(z_score, 2),
                        },
                    )
                    alerts_this_interval.append(alert)

        # Deduplicate (prevent flooding same alert type multiple times/interval)
        seen_types = set()
        deduped = []
        for a in alerts_this_interval:
            key = (a["type"], a.get("source_ip"))
            if key not in seen_types:
                seen_types.add(key)
                deduped.append(a)

        # Persist and buffer
        for alert in deduped:
            self._persist_alert(alert)
            logger.warning(
                "ALERT [%s] %s — %s", alert["severity"], alert["type"], alert["message"]
            )

        return deduped

    def get_recent_alerts(self, limit: int = 100) -> List[Dict]:
        """Return the most recent alerts from the in-memory buffer."""
        alerts = list(self._alert_buffer)
        return alerts[:limit]

    # ─── Internal Helpers ─────────────────────────────────────────────────────

    def _make_alert(
        self,
        alert_type: str,
        severity:   str,
        source_ip:  Optional[str],
        message:    str,
        details:    Dict,
    ) -> Dict:
        """Construct a standardized alert dictionary."""
        return {
            "type":      alert_type,
            "severity":  severity,
            "source_ip": source_ip,
            "message":   message,
            "details":   details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _persist_alert(self, alert: Dict) -> None:
        """Add alert to in-memory buffer and optionally persist to MongoDB."""
        self._alert_buffer.appendleft(alert)  # newest first
        if self.db:
            try:
                self.db.insert_alert(alert)
            except Exception as exc:  # noqa: BLE001
                logger.error("Alert persistence failed: %s", exc)
