import os

NETWORK_INTERFACE = os.getenv("NET_INTERFACE", "Wi-Fi")

# Maximum packets to store in the in-memory queue before the analyzer catches up.
PACKET_QUEUE_MAX = 10_000

# How often (seconds) the analyzer flushes metrics to MongoDB.
ANALYSIS_INTERVAL = 5  # seconds

# ─── MongoDB ──────────────────────────────────────────────────────────────────
MONGO_URI      = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB_NAME  = "netmon"

# Collection names
COL_PACKETS     = "packets"        # individual packet summaries
COL_STATS       = "traffic_stats"  # aggregated per-interval metrics
COL_ALERTS      = "alerts"         # anomaly/alert records
COL_CONNECTIONS = "connections"    # active connection tracking

# How many days to retain raw packet records before auto-expiry (TTL index)
PACKET_TTL_DAYS = 1

# ─── Flask API ────────────────────────────────────────────────────────────────
FLASK_HOST  = "0.0.0.0"
FLASK_PORT  = 5000
FLASK_DEBUG = False  # Never True in production

SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_ME_IN_PRODUCTION_abc123xyz")

# ─── Dashboard Authentication ────────────────────────────────────────────────
DASHBOARD_USERNAME = os.getenv("DASH_USER", "admin")
DASHBOARD_PASSWORD = os.getenv("DASH_PASS", "netmon2024")

# Session lifetime in minutes
SESSION_LIFETIME_MINUTES = 60

# ─── Alert Thresholds ────────────────────────────────────────────────────────
# Traffic spike: packets/sec threshold
ALERT_PPS_THRESHOLD = 300           # pps — potential DoS if exceeded

# Rate limiting: max packets from a single IP within the window
ALERT_IP_RATE_LIMIT  = 500          # packets per analysis interval

# Suspicious ports that trigger an alert when accessed
ALERT_SUSPICIOUS_PORTS = {
    22, 23, 3389,              # SSH, Telnet, RDP
    1433, 3306, 5432, 27017,   # Common databases
    4444, 5555, 6666, 9001,    # Common RAT/C2 ports
    31337, 12345,              # Well-known backdoor ports
}

# Z-score threshold for statistical anomaly detection (sigma)
ANOMALY_ZSCORE_THRESHOLD = 3.0

# Minimum data points before statistical anomaly kicks in
ANOMALY_MIN_HISTORY = 10

# Port scan detection: distinct ports from one IP within interval
ALERT_PORT_SCAN_THRESHOLD = 20

# ─── Logging ─────────────────────────────────────────────────────────────────
LOG_DIR      = "logs"
LOG_FILENAME = "netmon.log"
LOG_MAX_BYTES   = 10 * 1024 * 1024   # 10 MB
LOG_BACKUP_COUNT = 5
LOG_LEVEL = "INFO"   # DEBUG | INFO | WARNING | ERROR

# ─── Exports ─────────────────────────────────────────────────────────────────
EXPORT_DIR = "exports"

# ─── Simulation Mode (for demo/testing without root) ─────────────────────────
SIMULATE_PACKET_RATE   = 80    # synthetic packets per second
SIMULATE_IPS           = [
    "192.168.1.10", "192.168.1.20", "192.168.1.30",
    "10.0.0.5",     "10.0.0.15",   "172.16.0.1",
    "8.8.8.8",      "1.1.1.1",     "192.168.1.1",
]
SIMULATE_SPIKE_CHANCE  = 0.05  # 5% chance of injecting a traffic spike
