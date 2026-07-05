# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] — 2024-07-05

### Added

- **Real-time web dashboard** with Chart.js visualizations
  - Live traffic-over-time line chart (packets/sec + bandwidth)
  - Protocol distribution doughnut chart
  - Top talkers table with usage bars
  - Live alerts feed panel
- **Flask REST API** with authenticated endpoints
  - `GET /api/stats/realtime` — latest computed metrics
  - `GET /api/stats/history` — historical traffic data
  - `GET /api/alerts` — alert list with filtering
  - `GET /api/top-talkers` — top IP addresses by volume
  - `GET /api/protocols` — protocol distribution
  - `GET /api/connections` — active connections
  - `GET /api/export/csv` — CSV download
  - `GET /api/export/json` — JSON download
  - `GET /api/status` — system health check
- **Anomaly detection engine** with five detection rules
  - Packets-per-second spike detection
  - Single-IP rate limiting
  - Suspicious port access detection
  - Port scan detection
  - Statistical Z-score bandwidth anomaly
- **Packet capture engine** (Scapy-based)
  - Live network sniffing with protocol classification
  - TCP flag decoding
  - Application-layer protocol identification (HTTP, HTTPS, DNS, SSH, etc.)
- **Simulation mode** for demo/testing without root privileges
  - Configurable synthetic traffic generation
  - Occasional spike injection for anomaly demo
- **MongoDB persistence** with TTL auto-expiry
  - Traffic stats collection with time-series indexing
  - Alert storage with compound indexes
  - Active connection snapshots
- **Session-based authentication** for dashboard access (Flask-Login)
- **CSV and JSON export** utilities
- **Centralized rotating logger** with file and console output
- **CLI interface** with Click (--simulate, --api-only, --interface, --port)
- **Comprehensive unit tests** (pytest) — all modules covered
- **Graceful shutdown** handling (SIGINT, SIGTERM)

### Architecture

- Modular design: capture → processing → database → API → frontend
- Thread-safe packet queue between capture and analyzer
- Dependency injection pattern for database and alert engine
- Flask application factory pattern with blueprints
- In-memory alert buffer with optional DB persistence

## [1.0.0] — 2024-06-01

### Added

- Initial project scaffold
- Basic packet capture functionality
- MongoDB integration prototype

---

[2.0.0]: https://github.com/Vara693/netmon/releases/tag/v2.0.0
[1.0.0]: https://github.com/Vara693/netmon/releases/tag/v1.0.0
