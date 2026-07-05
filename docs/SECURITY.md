# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 2.0.x   | ✅ Active support  |
| < 2.0   | ❌ No support      |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue
in NetMon, please report it responsibly.

### How to Report

1. **Do NOT open a public GitHub issue** for security vulnerabilities
2. Send a detailed report to: pvaradraj2@gmail.com
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours of your report
- **Assessment**: We will evaluate the severity within 5 business days
- **Resolution**: Critical issues will be patched as soon as possible
- **Disclosure**: We will coordinate disclosure timing with you

## Security Best Practices for Deployment

NetMon handles network traffic data and requires elevated system privileges.
Follow these guidelines to deploy securely:

### 1. Authentication & Secrets

- **Change default credentials** before any deployment:
  - Set `DASH_USER` and `DASH_PASS` environment variables
  - Set a strong `SECRET_KEY` environment variable
- **Never commit secrets** to version control
- Use `.env` files or environment variables for all sensitive configuration
- The default credentials (`admin` / `netmon2024`) are for development only

### 2. Network Exposure

- **Do NOT expose the dashboard** on public networks without additional protection
- Use a **reverse proxy** (Nginx, Caddy) with TLS termination in production
- Bind Flask to `127.0.0.1` instead of `0.0.0.0` when not using a reverse proxy
- Configure firewall rules to restrict access to the dashboard port (default: 5000)

### 3. Packet Capture Privileges

- The capture engine requires **root/sudo** privileges for live sniffing
- Run with **minimal privileges**: only grant `CAP_NET_RAW` capability instead
  of full root access when possible:
  ```bash
  sudo setcap cap_net_raw=eip $(which python3)
  ```
- Use **simulation mode** (`--simulate`) for demos and testing — no root needed

### 4. MongoDB Security

- Enable **authentication** on your MongoDB instance
- Use a **dedicated database user** with minimal permissions (read/write to
  `netmon` database only)
- Do **NOT expose MongoDB** on public interfaces without authentication
- Use **TLS/SSL** for MongoDB connections in production
- Consider using [MongoDB Atlas](https://www.mongodb.com/atlas) for managed
  security

### 5. Data Handling

- Packet capture data may contain **sensitive network information**
- Configure `PACKET_TTL_DAYS` in `config.py` to auto-expire old data
- Restrict access to exported CSV/JSON files
- Be mindful of data retention regulations (GDPR, etc.) in your jurisdiction

### 6. CORS Configuration

- The default CORS policy (`origins: "*"`) is permissive for development
- In production, restrict allowed origins to your specific domain:
  ```python
  CORS(app, resources={r"/api/*": {"origins": "https://your-domain.com"}})
  ```

### 7. Session Security

- Session cookies are configured with `HttpOnly` and `SameSite=Lax` flags
- Set `SESSION_COOKIE_SECURE = True` when using HTTPS
- Review `SESSION_LIFETIME_MINUTES` and adjust for your security requirements

## Known Security Considerations

| Area                    | Risk Level | Mitigation                                |
|-------------------------|------------|-------------------------------------------|
| Default credentials     | High       | Change via environment variables           |
| HTTP (no TLS)           | High       | Deploy behind HTTPS reverse proxy          |
| Root requirement        | Medium     | Use `CAP_NET_RAW` or simulation mode       |
| Open CORS policy        | Medium     | Restrict origins in production             |
| MongoDB without auth    | High       | Enable MongoDB authentication              |
| Packet data sensitivity | Medium     | Configure TTL, restrict export access      |

## Security Updates

Security patches will be released as soon as possible after a vulnerability
is confirmed. Watch the repository for release notifications.

---

Thank you for helping keep NetMon and its users safe! 🛡️
