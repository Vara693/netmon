# =============================================================================
# capture/packet_capture.py — Packet Capture Engine
# =============================================================================
# Uses Scapy to sniff live network packets and push parsed summaries into a
# thread-safe queue consumed by the Traffic Analyzer.
#
# In simulation mode, generates synthetic packets without requiring root or
# a physical network interface — useful for demos and testing.

import queue
import random
import threading
import time
from datetime import datetime, timezone
from typing import Optional

import config
from utils.logger import get_logger

logger = get_logger(__name__)


# ─── Packet Summary Schema ────────────────────────────────────────────────────
# Each item pushed to the queue is a plain dict:
#
#   {
#     "timestamp"  : str (ISO 8601 UTC),
#     "src_ip"     : str,
#     "dst_ip"     : str,
#     "src_port"   : int | None,
#     "dst_port"   : int | None,
#     "protocol"   : str,   # "TCP" | "UDP" | "ICMP" | "ARP" | "OTHER"
#     "size"       : int,   # bytes
#     "flags"      : str,   # TCP flags (e.g. "S", "SA") or ""
#   }


class PacketCaptureEngine:
    """
    Captures network packets and populates a shared queue.

    Args:
        packet_queue: Thread-safe queue shared with the traffic analyzer.
        interface:    NIC to sniff (e.g. "eth0"). None → Scapy picks default.
        simulate:     If True, generate synthetic packets instead of sniffing.
    """

    def __init__(
        self,
        packet_queue: queue.Queue,
        interface: Optional[str] = None,
        simulate: bool = False,
    ):
        self.packet_queue = packet_queue
        self.interface    = interface or config.NETWORK_INTERFACE
        self.simulate     = simulate
        self._stop_event  = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.captured     = 0   # total packets captured since start

    # ─── Public API ───────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the capture thread."""
        logger.info(
            "PacketCaptureEngine starting — mode=%s interface=%s",
            "SIMULATE" if self.simulate else "LIVE",
            self.interface,
        )
        target = self._simulate_loop if self.simulate else self._capture_loop
        self._thread = threading.Thread(target=target, daemon=True, name="CaptureThread")
        self._thread.start()

    def stop(self) -> None:
        """Signal the capture thread to stop and wait for it."""
        logger.info("PacketCaptureEngine stopping…")
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ─── Live Capture (Scapy) ─────────────────────────────────────────────────

    def _capture_loop(self) -> None:
        """
        Main loop for live packet sniffing.
        Runs Scapy's sniff() in a loop so we can check the stop event.
        Each sniff() call runs for 2 seconds before checking for stop.
        """
        try:
            from scapy.all import sniff  # type: ignore
        except ImportError:
            logger.error("Scapy not installed — falling back to simulation mode")
            self._simulate_loop()
            return

        logger.info("Sniffing on interface: %s", self.interface)
        while not self._stop_event.is_set():
            try:
                sniff(
                    iface=self.interface,
                    prn=self._process_packet,
                    store=False,
                    timeout=2,          # re-check stop_event every 2 s
                    count=0,            # unlimited packets per window
                )
            except PermissionError:
                logger.critical(
                    "Permission denied — run with sudo/root for live capture"
                )
                break
            except Exception as exc:  # noqa: BLE001
                logger.error("Sniff error: %s — retrying in 1s", exc)
                time.sleep(1)

    def _process_packet(self, pkt) -> None:
        """Scapy callback — parse a single raw packet into a summary dict."""
        try:
            from scapy.all import IP, TCP, UDP, ICMP, ARP  # type: ignore

            summary = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "src_ip":    None,
                "dst_ip":    None,
                "src_port":  None,
                "dst_port":  None,
                "protocol":  "OTHER",
                "size":      len(pkt),
                "flags":     "",
            }

            if pkt.haslayer(IP):
                ip = pkt[IP]
                summary["src_ip"] = ip.src
                summary["dst_ip"] = ip.dst

                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    summary["protocol"] = "TCP"
                    summary["src_port"] = tcp.sport
                    summary["dst_port"] = tcp.dport
                    # Decode TCP flags bitmask to human-readable string
                    summary["flags"] = _decode_tcp_flags(tcp.flags)

                    # Classify well-known app-layer protocols
                    port = min(tcp.sport, tcp.dport)
                    if port in (80, 8080):
                        summary["protocol"] = "HTTP"
                    elif port == 443:
                        summary["protocol"] = "HTTPS"
                    elif port == 22:
                        summary["protocol"] = "SSH"
                    elif port == 53:
                        summary["protocol"] = "DNS"

                elif pkt.haslayer(UDP):
                    udp = pkt[UDP]
                    summary["src_port"] = udp.sport
                    summary["dst_port"] = udp.dport

                    sport = udp.sport
                    dport = udp.dport
                    either_port = {sport, dport}   # use a set, check both ports individually

                    if 53 in either_port:
                        summary["protocol"] = "DNS"
                    elif 5353 in either_port:
                        summary["protocol"] = "mDNS"
                    elif 443 in either_port:
                        summary["protocol"] = "QUIC"
                    elif 1900 in either_port:
                        summary["protocol"] = "SSDP"
                    elif 67 in either_port or 68 in either_port:
                        summary["protocol"] = "DHCP"
                    elif 123 in either_port:
                        summary["protocol"] = "NTP"
                    elif either_port & {6881,6882,6883,6884,6885,6886,6969,1337,2710}:
                        summary["protocol"] = "TORRENT"
                    else:
                        summary["protocol"] = "UDP"  

                elif pkt.haslayer(ICMP):
                    summary["protocol"] = "ICMP"

            elif pkt.haslayer(ARP):
                summary["protocol"]  = "ARP"
                summary["src_ip"]    = pkt[ARP].psrc
                summary["dst_ip"]    = pkt[ARP].pdst

            # Drop packets with no parseable IP
            if summary["src_ip"] is None:
                return

            self._enqueue(summary)

        except Exception as exc:  # noqa: BLE001
            logger.debug("Packet parse error (skipped): %s", exc)

    # ─── Simulation Mode ──────────────────────────────────────────────────────

    def _simulate_loop(self) -> None:
        """
        Generate realistic synthetic traffic for demo purposes.
        Produces a mix of protocols, occasional spikes, and suspicious activity.
        """
        logger.info("Running in SIMULATION mode — no root required")
        protocols  = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "ARP"]
        weights    = [30,    20,    10,     15,     18,      5,     2  ]
        src_ips    = config.SIMULATE_IPS
        dst_ips    = config.SIMULATE_IPS + ["8.8.8.8", "1.1.1.1", "93.184.216.34"]
        ports      = [80, 443, 22, 53, 8080, 3306, 5432, 3389, 4444, 6379, 8443]

        interval   = 1.0 / config.SIMULATE_PACKET_RATE  # seconds per packet

        while not self._stop_event.is_set():
            # Occasionally inject a traffic spike for anomaly demo
            burst = 1
            if random.random() < config.SIMULATE_SPIKE_CHANCE:
                burst = random.randint(20, 60)
                logger.debug("Injecting simulated traffic spike (%d pkts)", burst)

            for _ in range(burst):
                proto   = random.choices(protocols, weights=weights, k=1)[0]
                src_ip  = random.choice(src_ips)
                dst_ip  = random.choice(dst_ips)
                src_port = random.choice(ports)
                dst_port = random.choice(ports)

                # Occasionally simulate suspicious port access
                if random.random() < 0.02:
                    dst_port = random.choice(list(config.ALERT_SUSPICIOUS_PORTS))

                summary = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "src_ip":   src_ip,
                    "dst_ip":   dst_ip,
                    "src_port": src_port if proto not in ("ICMP", "ARP") else None,
                    "dst_port": dst_port if proto not in ("ICMP", "ARP") else None,
                    "protocol": proto,
                    "size":     random.randint(40, 1500),
                    "flags":    random.choice(["S", "SA", "A", "F", ""]) if proto in ("TCP", "HTTP", "HTTPS") else "",
                }
                self._enqueue(summary)

            time.sleep(interval)

    # ─── Internal Helpers ─────────────────────────────────────────────────────

    def _enqueue(self, summary: dict) -> None:
        """Push a packet summary to the queue (discard if full to avoid blocking)."""
        try:
            self.packet_queue.put_nowait(summary)
            self.captured += 1
        except queue.Full:
            logger.warning("Packet queue full — dropping packet (analyzer too slow?)")


# ─── Utility ──────────────────────────────────────────────────────────────────

def _decode_tcp_flags(flags_int: int) -> str:
    """Convert Scapy's integer TCP flags to a readable string (e.g. 'SA', 'F')."""
    flag_map = {
        0x01: "F",   # FIN
        0x02: "S",   # SYN
        0x04: "R",   # RST
        0x08: "P",   # PSH
        0x10: "A",   # ACK
        0x20: "U",   # URG
    }
    return "".join(char for bit, char in flag_map.items() if flags_int & bit)
