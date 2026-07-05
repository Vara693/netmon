# Contributing to NetMon

Thank you for your interest in contributing to NetMon! This document provides
guidelines and information to help you get started.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code. Please report
unacceptable behavior to the project maintainers.

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/netmon.git
   cd netmon
   ```
3. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

### Prerequisites

- Python 3.9 or higher
- MongoDB (local instance or [MongoDB Atlas](https://www.mongodb.com/atlas))
- Linux/macOS recommended (root/sudo required for live packet capture)
- Windows: Install [Npcap](https://npcap.com/) for Scapy support

### Installation

```bash
# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt
```

### Configuration

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
2. Update `.env` with your local settings (MongoDB URI, network interface, etc.)
3. Alternatively, edit `config.py` directly for development

### Running the Application

```bash
# Simulation mode (no root/admin required — great for development)
python3 main.py --simulate

# Live capture mode (requires root/sudo)
sudo python3 main.py

# API-only mode (no packet capture)
python3 main.py --api-only
```

### Running Tests

```bash
# Run the full test suite
python3 -m pytest tests/ -v

# Run with coverage report
python3 -m pytest tests/ -v --cov=. --cov-report=term-missing
```

## How to Contribute

### Types of Contributions Welcome

- 🐛 **Bug fixes** — Find something broken? Fix it!
- ✨ **New features** — Check the [roadmap](#feature-roadmap) or propose your own
- 📖 **Documentation** — Improve README, docstrings, or add examples
- 🧪 **Tests** — Increase test coverage or add edge-case tests
- 🎨 **UI improvements** — Enhance the dashboard design or UX
- ⚡ **Performance** — Optimize packet processing or database queries

### Feature Roadmap

The following enhancements are planned and open for contributions:

1. ML-based anomaly detection (Isolation Forest / Autoencoder)
2. GeoIP mapping with MaxMind GeoLite2
3. Email/Slack alert notifications
4. Deep packet inspection (DNS query tracking, HTTP method analysis)
5. Multi-interface capture support
6. Docker/docker-compose deployment
7. Prometheus + Grafana integration
8. WebSocket streaming (replace HTTP polling)

## Pull Request Process

1. **Ensure your code passes all tests**:
   ```bash
   python3 -m pytest tests/ -v
   ```

2. **Follow the coding standards** outlined below

3. **Update documentation** if your changes affect:
   - Public API endpoints
   - Configuration options
   - Setup or usage instructions

4. **Write descriptive commit messages**:
   ```
   feat: add GeoIP mapping for source IP addresses
   fix: handle queue overflow in packet capture engine
   docs: update API endpoint documentation
   test: add edge-case tests for anomaly detector
   ```

5. **Submit your pull request** with:
   - A clear description of what changed and why
   - Reference to any related issues (e.g., `Closes #42`)
   - Screenshots if the change affects the UI

6. **Wait for review** — maintainers will review your PR and may request changes

## Coding Standards

### Python Style

- Follow **PEP 8** conventions
- Use **type hints** for function signatures
- Write **docstrings** for all public classes and methods
- Keep functions focused — single responsibility principle
- Use the project's centralized logger (`from utils.logger import get_logger`)

### Project Structure

- **Capture logic** → `capture/`
- **Data processing** → `processing/`
- **Database operations** → `database/`
- **API endpoints** → `api/`
- **Alert detection** → `alerts/`
- **Shared utilities** → `utils/`
- **Frontend assets** → `frontend/`
- **Tests** → `tests/`

### Commit Message Convention

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

| Prefix   | Purpose                          |
|----------|----------------------------------|
| `feat`   | New feature                      |
| `fix`    | Bug fix                          |
| `docs`   | Documentation changes            |
| `test`   | Adding or updating tests         |
| `refactor` | Code restructuring (no behavior change) |
| `perf`   | Performance improvement          |
| `chore`  | Maintenance tasks, dependencies  |
| `style`  | Code formatting (no logic change)|

## Reporting Bugs

When reporting bugs, please include:

1. **System information**: OS, Python version, MongoDB version
2. **Steps to reproduce**: Minimal steps to trigger the bug
3. **Expected behavior**: What you expected to happen
4. **Actual behavior**: What actually happened
5. **Logs**: Relevant output from `logs/netmon.log`
6. **Screenshots**: If the bug is UI-related

Use the **Bug Report** issue template when available.

## Suggesting Features

Feature suggestions are welcome! Please:

1. **Check existing issues** to avoid duplicates
2. **Describe the use case** — what problem does this feature solve?
3. **Propose a solution** — how do you envision it working?
4. **Consider scope** — is this a small improvement or a large architectural change?

Use the **Feature Request** issue template when available.

---

Thank you for contributing to NetMon! 🚀
