<p align="center">
  <img src="https://img.shields.io/badge/python-3.9+-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/Flask-3.0-lightgrey?style=flat-square&logo=flask" alt="Flask 3.0">
  <img src="https://img.shields.io/badge/MongoDB-Atlas%20%7C%20Local-47A248?style=flat-square&logo=mongodb&logoColor=white" alt="MongoDB">
  <img src="https://img.shields.io/badge/Scapy-2.5-orange?style=flat-square" alt="Scapy 2.5">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT License">
</p>

# NetMon — Real-Time Network Monitoring & Traffic Analysis System

A modular, real-time network monitoring system with anomaly detection, a REST API, and a live web dashboard. Built with **Python**, **Flask**, **Scapy**, **MongoDB**, and **Chart.js**.

> **Quick Start:** `python main.py --simulate` — launches a full demo with synthetic traffic. No root, no MongoDB required.

---

## ✨ Features

| Category | Details |
|---|---|
| **Live Packet Capture** | Scapy-based engine with protocol classification (TCP, UDP, ICMP, HTTP, HTTPS, DNS, SSH, ARP, QUIC, mDNS, SSDP, DHCP, NTP) |
| **Real-Time Dashboard** | Chart.js-powered web UI with traffic charts, protocol distribution, top talkers, and alert feed |
| **Anomaly Detection** | 5-rule engine: traffic spikes, IP rate limiting, suspicious ports, port scans, Z-score bandwidth anomalies |
| **REST API** | 10 authenticated JSON endpoints for stats, history, alerts, connections, and data export |
| **Simulation Mode** | Full-featured synthetic traffic generator — no root or hardware required |
| **Data Export** | One-click CSV and JSON export from the dashboard |
| **MongoDB Persistence** | TTL auto-expiry, compound indexes, graceful fallback when DB is unavailable |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    NETWORK MONITORING SYSTEM                        │
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐   │
│  │   CAPTURE    │    │  PROCESSING  │    │      DATABASE        │   │
│  │   ENGINE     │───▶│   MODULE     │───▶│      (MongoDB)      │   │
│  │  (Scapy)     │    │              │    │                      │   │
│  │              │    │ • Bandwidth  │    │ • packets            │   │
│  │ • Sniff pkts │    │ • Protocols  │    │ • traffic_stats      │   │
│  │ • Parse hdrs │    │ • Top IPs    │    │ • alerts             │   │
│  │ • Queue pkts │    │ • Pkt rate   │    │ • connections        │   │
│  └──────────────┘    └──────┬───────┘    └──────────┬───────────┘   │
│                             │                       │               │
│                     ┌───────▼────────┐              │               │
│                     │  ALERT ENGINE  │              │               │
│                     │                │              │               │
│                     │ • DoS detect   │              │               │
│                     │ • Port scan    │              │               │
│                     │ • Rate limits  │              │               │
│                     └───────┬────────┘              │               │
│                             │                       │               │
│                    ┌────────▼───────────────────────▼────────────┐  │
│                    │            FLASK REST API                   │  │
│                    │                                             │  │
│                    │  GET /api/stats/realtime                    │  │
│                    │  GET /api/stats/history                     │  │
│                    │  GET /api/alerts                            │  │
│                    │  GET /api/top-talkers                       │  │
│                    │  GET /api/protocols                         │  │
│                    │  GET /api/connections                       │  │
│                    │  GET /api/export/csv                        │  │
│                    └────────────────┬────────────────────────────┘  │
│                                     │                               │
│                    ┌────────────────▼────────────────────────────┐  │
│                    │           WEB DASHBOARD                     │  │
│                    │                                             │  │
│                    │  • Real-time traffic chart (Chart.js)       │  │
│                    │  • Protocol distribution (Doughnut)         │  │
│                    │  • Top talkers table                        │  │
│                    │  • Active connections feed                  │  │
│                    │  • Live alerts panel                        │  │
│                    └─────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📂 Project Structure

```
netmon/
├── main.py                    # Application entry point (CLI)
├── config.py                  # Global configuration
├── requirements.txt           # Python dependencies
├── .env.example               # Environment variable template
├── LICENSE                    # MIT License
│
├── docs/
│   ├── CHANGELOG.md           # Version history
│   ├── CONTRIBUTING.md        # Contribution guidelines
│   ├── CODE_OF_CONDUCT.md     # Community standards
│   └── SECURITY.md            # Security policy
│
├── capture/
│   ├── __init__.py
│   └── packet_capture.py      # Scapy-based packet sniffer
│
├── processing/
│   ├── __init__.py
│   └── traffic_analyzer.py    # Aggregation & metric computation
│
├── database/
│   ├── __init__.py
│   └── db_handler.py          # MongoDB CRUD operations
│
├── api/
│   ├── __init__.py
│   └── routes.py              # Flask REST API endpoints
│
├── alerts/
│   ├── __init__.py
│   └── anomaly_detector.py    # Rule-based + statistical detection
│
├── utils/
│   ├── __init__.py
│   ├── logger.py              # Centralized rotating logger
│   └── exporter.py            # CSV/JSON export utilities
│
├── frontend/
│   ├── templates/
│   │   ├── dashboard.html     # Main dashboard template
│   │   └── login.html         # Authentication page
│   └── static/
│       ├── styles/
│       │   └── style.css      # Dashboard styles
│       └── js/
│           └── dashboard.js   # Chart.js real-time updates
│
├── tests/
│   └── test_modules.py        # Unit tests (pytest)
│
├── logs/                      # Auto-generated log files
└── exports/                   # CSV/JSON exports (runtime)
```

---

## ⚙️ Setup

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.9+ | Required |
| MongoDB | 4.4+ | Optional — system runs without it |
| Npcap | Latest | Windows only — required for Scapy |
| Root/sudo | — | Live capture only — not needed for simulation |

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/netmon.git
cd netmon

# 2. Create a virtual environment
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
# venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env with your settings (MongoDB URI, credentials, etc.)
```

### Find Your Network Interface

```bash
# Linux
ip link show

# macOS
ifconfig

# Windows
ipconfig /all
```

---

## 🚀 Usage

### Option A: Simulation Mode *(Recommended for getting started)*

```bash
python main.py --simulate
```

No root, no MongoDB, no hardware — generates synthetic traffic for a full demo.

### Option B: Live Capture

```bash
# Requires root/sudo for raw packet access
sudo python3 main.py

# Override the network interface
sudo python3 main.py --interface eth0
```

### Option C: API Only

```bash
python main.py --api-only
```

### CLI Options

| Flag | Description | Default |
|---|---|---|
| `--simulate` | Generate synthetic traffic | `False` |
| `--api-only` | Start API + dashboard, skip capture | `False` |
| `--interface IFACE` | Network interface to capture on | From `config.py` |
| `--port PORT` | Web dashboard port | `5000` |

### Access the Dashboard

Open **http://localhost:5000** in your browser.

Default credentials (change in `.env`):
- **Username:** `admin`
- **Password:** `netmon2024`

---

## 📡 API Reference

All API endpoints (except `/api/status`) require authentication.

| Method | Endpoint | Description | Query Parameters |
|---|---|---|---|
| `GET` | `/api/status` | System health check | — |
| `GET` | `/api/stats/realtime` | Latest computed metrics | — |
| `GET` | `/api/stats/history` | Historical traffic data | `minutes`, `limit` |
| `GET` | `/api/alerts` | Alert list | `limit`, `severity`, `minutes`, `source` |
| `GET` | `/api/top-talkers` | Top IPs by traffic volume | — |
| `GET` | `/api/protocols` | Protocol distribution (%) | — |
| `GET` | `/api/connections` | Active connections | `limit` |
| `GET` | `/api/export/csv` | Download stats as CSV | — |
| `GET` | `/api/export/json` | Download stats as JSON | — |

<details>
<summary><strong>Example Responses</strong></summary>

**`GET /api/stats/realtime`**
```json
{
  "packets_per_second": 142,
  "bandwidth_mbps": 1.87,
  "total_packets": 45823,
  "total_bytes": 62451200,
  "active_connections": 23,
  "timestamp": "2024-01-15T10:30:45Z"
}
```

**`GET /api/top-talkers`**
```json
{
  "top_talkers": [
    { "ip": "192.168.1.105", "packets": 8241, "bytes": 12582400, "percentage": 18.2 },
    { "ip": "10.0.0.15", "packets": 5103, "bytes": 4194304, "percentage": 11.1 }
  ]
}
```

**`GET /api/alerts`**
```json
{
  "alerts": [
    {
      "type": "TRAFFIC_SPIKE",
      "severity": "HIGH",
      "source_ip": "192.168.1.50",
      "message": "Packet rate 450 pps exceeds threshold 300 pps",
      "timestamp": "2024-01-15T10:28:12Z"
    }
  ]
}
```

</details>

---

## 🧪 Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ -v --cov=. --cov-report=term-missing
```

All tests use mocking — no network, MongoDB, or root access required.

---

## 🧩 Module Overview

| Module | File | Responsibility |
|---|---|---|
| **Capture Engine** | `capture/packet_capture.py` | Sniffs raw packets via Scapy, extracts headers, feeds a thread-safe queue |
| **Traffic Analyzer** | `processing/traffic_analyzer.py` | Consumes packet queue, computes bandwidth/protocol stats/top-talkers per interval |
| **Database Handler** | `database/db_handler.py` | MongoDB CRUD: inserts summaries, queries history, stores alerts, manages TTL |
| **Alert Engine** | `alerts/anomaly_detector.py` | Rule-based + Z-score anomaly detection with in-memory buffer |
| **REST API** | `api/routes.py` | Flask endpoints with blueprints, session auth, CORS |
| **Dashboard** | `frontend/` | HTML/CSS/JS with Chart.js for live visualization |
| **Logger** | `utils/logger.py` | Rotating file + console logging across all modules |
| **Exporter** | `utils/exporter.py` | CSV/JSON serialization for API downloads and file export |

---

## 🛡️ Security

> ⚠️ **Important:** Change default credentials and secret keys before any deployment.

See [SECURITY.md](docs/SECURITY.md) for the full security policy, including:

- Vulnerability reporting process
- Deployment hardening checklist
- Known security considerations

**Quick checklist:**
- [ ] Set `DASH_USER`, `DASH_PASS`, and `SECRET_KEY` via environment variables
- [ ] Deploy behind HTTPS (reverse proxy with TLS)
- [ ] Enable MongoDB authentication
- [ ] Restrict CORS origins for production

---

## 🗺️ Roadmap

- [ ] ML-based anomaly detection (Isolation Forest / Autoencoder)
- [ ] GeoIP mapping with MaxMind GeoLite2
- [ ] Email / Slack alert notifications
- [ ] Deep packet inspection (DNS queries, HTTP methods)
- [ ] Multi-interface capture
- [ ] Docker / docker-compose deployment
- [ ] Prometheus + Grafana integration
- [ ] WebSocket streaming (replace HTTP polling)
- [ ] PCAP export for Wireshark analysis
- [ ] Full RBAC with JWT tokens

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) for
guidelines on how to get started, coding standards, and the pull request process.

This project follows the [Contributor Covenant Code of Conduct](docs/CODE_OF_CONDUCT.md).

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE)
file for details.

---

<p align="center">
  <sub>Built with ❤️ for network security enthusiasts</sub>
</p>
