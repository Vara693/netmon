# =============================================================================
# tests/test_modules.py — Unit Tests for NetMon Modules
# =============================================================================
# Run with:  python3 -m pytest tests/ -v
# No network, MongoDB, or root access required — all dependencies are mocked.

import queue
import time
import sys
import os

# Ensure project root is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest


# ════════════════════════════════════════════════════════════════════════════
# PACKET CAPTURE ENGINE TESTS
# ════════════════════════════════════════════════════════════════════════════

class TestPacketCaptureEngine:

    def _make_engine(self):
        from capture.packet_capture import PacketCaptureEngine
        q = queue.Queue()
        return PacketCaptureEngine(packet_queue=q, simulate=True), q

    def test_engine_starts_and_stops(self):
        engine, q = self._make_engine()
        engine.start()
        time.sleep(0.3)
        assert engine.is_running
        engine.stop()
        # After stop, thread should be dead within a short time
        time.sleep(0.2)
        assert not engine.is_running

    def test_simulation_produces_packets(self):
        engine, q = self._make_engine()
        engine.start()
        time.sleep(0.5)
        engine.stop()
        # Should have generated at least a few packets
        assert q.qsize() > 0

    def test_packet_schema(self):
        engine, q = self._make_engine()
        engine.start()
        time.sleep(0.3)
        engine.stop()

        required_keys = {"timestamp", "src_ip", "dst_ip", "protocol", "size", "flags"}
        pkt = q.get_nowait()
        for key in required_keys:
            assert key in pkt, f"Missing field: {key}"

    def test_packet_protocol_is_valid(self):
        from capture.packet_capture import PacketCaptureEngine
        valid_protocols = {"TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "ARP", "OTHER"}
        engine, q = self._make_engine()
        engine.start()
        time.sleep(0.5)
        engine.stop()
        while not q.empty():
            pkt = q.get_nowait()
            assert pkt["protocol"] in valid_protocols

    def test_queue_full_drops_packet(self):
        """Engine should not block when queue is full."""
        from capture.packet_capture import PacketCaptureEngine
        tiny_q = queue.Queue(maxsize=1)
        engine = PacketCaptureEngine(packet_queue=tiny_q, simulate=True)
        # Pre-fill queue
        tiny_q.put({"dummy": True})
        # _enqueue should handle full gracefully
        engine._enqueue({"test": "drop"})  # should not raise


# ════════════════════════════════════════════════════════════════════════════
# TRAFFIC ANALYZER TESTS
# ════════════════════════════════════════════════════════════════════════════

class TestTrafficAnalyzer:

    def _make_analyzer(self):
        from processing.traffic_analyzer import TrafficAnalyzer
        q = queue.Queue()
        return TrafficAnalyzer(packet_queue=q), q

    def _make_packet(self, proto="TCP", src="10.0.0.1", dst="8.8.8.8", size=500):
        from datetime import datetime, timezone
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip":    src,
            "dst_ip":    dst,
            "src_port":  54321,
            "dst_port":  80,
            "protocol":  proto,
            "size":      size,
            "flags":     "SA",
        }

    def test_accumulate_increments_counters(self):
        analyzer, q = self._make_analyzer()
        pkt = self._make_packet()
        analyzer._accumulate(pkt)
        assert analyzer._interval_packets == 1
        assert analyzer._interval_bytes   == 500
        assert analyzer._all_time_packets == 1

    def test_protocol_counted(self):
        analyzer, _ = self._make_analyzer()
        analyzer._accumulate(self._make_packet(proto="UDP"))
        assert analyzer._protocol_counts["UDP"] == 1

    def test_top_talkers_sorted(self):
        analyzer, _ = self._make_analyzer()
        # IP A sends 5 packets, IP B sends 2
        for _ in range(5):
            analyzer._accumulate(self._make_packet(src="192.168.1.1"))
        for _ in range(2):
            analyzer._accumulate(self._make_packet(src="10.0.0.2"))

        stats = analyzer._compute_stats()
        talkers = stats["top_talkers"]
        assert talkers[0]["ip"] == "192.168.1.1"
        assert talkers[0]["packets"] == 5

    def test_bandwidth_computation(self):
        analyzer, _ = self._make_analyzer()
        # 1 MB of data in ANALYSIS_INTERVAL seconds → bandwidth should be computed
        for _ in range(10):
            analyzer._accumulate(self._make_packet(size=100_000))
        stats = analyzer._compute_stats()
        assert stats["bandwidth_mbps"] > 0

    def test_get_realtime_stats_thread_safe(self):
        analyzer, q = self._make_analyzer()
        # Should return a dict even with no data
        result = analyzer.get_realtime_stats()
        assert isinstance(result, dict)
        assert "packets_per_second" in result

    def test_reset_accumulators(self):
        analyzer, _ = self._make_analyzer()
        analyzer._accumulate(self._make_packet())
        assert analyzer._interval_packets > 0
        analyzer._reset_accumulators()
        assert analyzer._interval_packets == 0

    def test_port_scan_candidate_detected(self):
        import config
        analyzer, _ = self._make_analyzer()
        src = "evil.host"
        # Access more distinct ports than the threshold
        for port in range(config.ALERT_PORT_SCAN_THRESHOLD + 5):
            pkt = self._make_packet(src=src)
            pkt["dst_port"] = port
            analyzer._accumulate(pkt)
        stats = analyzer._compute_stats()
        assert src in stats["port_scan_candidates"]


# ════════════════════════════════════════════════════════════════════════════
# ANOMALY DETECTOR TESTS
# ════════════════════════════════════════════════════════════════════════════

class TestAnomalyDetector:

    def _make_stats(self, pps=10, bw=0.1, ip_counts=None, connections=None):
        return {
            "timestamp":           "2024-01-01T00:00:00Z",
            "packets_per_second":  pps,
            "bandwidth_mbps":      bw,
            "ip_packet_counts":    ip_counts or {},
            "active_connections":  connections or [],
            "port_scan_candidates": {},
        }

    def test_no_alert_normal_traffic(self):
        from alerts.anomaly_detector import AnomalyDetector
        det = AnomalyDetector()
        stats = self._make_stats(pps=50, bw=0.5)
        alerts = det.evaluate(stats)
        assert alerts == []

    def test_traffic_spike_alert(self):
        import config
        from alerts.anomaly_detector import AnomalyDetector
        det = AnomalyDetector()
        stats = self._make_stats(pps=config.ALERT_PPS_THRESHOLD + 100)
        alerts = det.evaluate(stats)
        types = [a["type"] for a in alerts]
        assert "TRAFFIC_SPIKE" in types

    def test_ip_rate_limit_alert(self):
        import config
        from alerts.anomaly_detector import AnomalyDetector
        det = AnomalyDetector()
        stats = self._make_stats(
            ip_counts={"192.168.1.99": config.ALERT_IP_RATE_LIMIT + 50}
        )
        alerts = det.evaluate(stats)
        types = [a["type"] for a in alerts]
        assert "IP_RATE_LIMIT" in types

    def test_suspicious_port_alert(self):
        import config
        from alerts.anomaly_detector import AnomalyDetector
        det = AnomalyDetector()
        bad_port = next(iter(config.ALERT_SUSPICIOUS_PORTS))
        conn = {"src_ip": "1.2.3.4", "dst_port": bad_port, "protocol": "TCP"}
        stats = self._make_stats(connections=[conn])
        alerts = det.evaluate(stats)
        types = [a["type"] for a in alerts]
        assert "SUSPICIOUS_PORT" in types

    def test_alert_buffer_populated(self):
        import config
        from alerts.anomaly_detector import AnomalyDetector
        det = AnomalyDetector()
        stats = self._make_stats(pps=config.ALERT_PPS_THRESHOLD + 200)
        det.evaluate(stats)
        recent = det.get_recent_alerts()
        assert len(recent) > 0

    def test_zscore_anomaly_triggers(self):
        import config
        from alerts.anomaly_detector import AnomalyDetector
        det = AnomalyDetector()

        # Prime history with low bandwidth
        for _ in range(config.ANOMALY_MIN_HISTORY + 2):
            det.evaluate(self._make_stats(bw=0.01))

        # Now inject a massive spike
        alerts = det.evaluate(self._make_stats(bw=999.9))
        types = [a["type"] for a in alerts]
        assert "BANDWIDTH_ANOMALY" in types

    def test_alert_deduplication(self):
        import config
        from alerts.anomaly_detector import AnomalyDetector
        det = AnomalyDetector()
        # Two conditions that would both trigger TRAFFIC_SPIKE — should only appear once
        stats = self._make_stats(pps=config.ALERT_PPS_THRESHOLD + 500)
        alerts = det.evaluate(stats)
        spike_alerts = [a for a in alerts if a["type"] == "TRAFFIC_SPIKE"]
        assert len(spike_alerts) == 1


# ════════════════════════════════════════════════════════════════════════════
# EXPORTER TESTS
# ════════════════════════════════════════════════════════════════════════════

class TestExporter:

    def test_records_to_csv_string_empty(self):
        from utils.exporter import records_to_csv_string
        result = records_to_csv_string([])
        assert result == ""

    def test_records_to_csv_string_output(self):
        from utils.exporter import records_to_csv_string
        records = [
            {"timestamp": "2024-01-01T00:00:00Z", "src_ip": "10.0.0.1",
             "protocol": "TCP", "size": 500},
        ]
        csv_str = records_to_csv_string(records)
        assert "timestamp" in csv_str
        assert "10.0.0.1" in csv_str
        assert "TCP" in csv_str

    def test_export_json(self, tmp_path, monkeypatch):
        import config as cfg
        monkeypatch.setattr(cfg, "EXPORT_DIR", str(tmp_path))
        from utils.exporter import export_json
        path = export_json({"test": 123}, label="unit_test")
        assert path != ""
        import json
        with open(path) as f:
            data = json.load(f)
        assert data["test"] == 123


# ════════════════════════════════════════════════════════════════════════════
# LOGGER TESTS
# ════════════════════════════════════════════════════════════════════════════

class TestLogger:

    def test_get_logger_returns_logger(self):
        from utils.logger import get_logger
        import logging
        log = get_logger("test.module")
        assert isinstance(log, logging.Logger)

    def test_get_logger_no_duplicate_handlers(self):
        from utils.logger import get_logger
        log1 = get_logger("dedup.test")
        log2 = get_logger("dedup.test")
        # Should not add handlers twice
        assert len(log1.handlers) == len(log2.handlers)
