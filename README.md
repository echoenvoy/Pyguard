# 🛡️ FlaskGuard — Custom Web Application Firewall

A lightweight, production-inspired WAF built with Flask that demonstrates layered security principles used in real enterprise systems.

##  Features

| Feature | Details |
|---|---|
| **Regex Detection** | 30+ patterns covering SQL Injection, XSS, Path Traversal, Command Injection |
| **ML Classifier** | Naive Bayes trained on real attack payloads (char n-gram TF-IDF) |
| **Rate Limiting** | Per-IP rate limiting via `flask-limiter` |
| **IP Blacklist** | Auto-bans after 5 strikes; manual ban/unban via dashboard |
| **Attack Logger** | JSON log + Python logging to `security.log` |
| **Admin Dashboard** | Real-time dashboard with charts, attack log, blacklist manager |

##  Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run
python app.py
```

Then open:
- **App**: http://127.0.0.1:5000
- **Dashboard**: http://127.0.0.1:5000/admin

## 📁 Project Structure

```
FlaskGuard/
├── app.py              # Main Flask app + middleware
├── security.py         # Regex-based attack detection
├── ml_classifier.py    # Naive Bayes ML model
├── ip_manager.py       # IP blacklist manager
├── attack_logger.py    # JSON + file logging
├── requirements.txt
├── templates/
│   ├── index.html      # Demo app with live tester
│   └── dashboard.html  # Admin security dashboard
└── logs/
    ├── attacks.json    # Structured attack events
    ├── security.log    # Python logger output
    └── blacklist.json  # Persisted IP blacklist
```

##  Detection Pipeline

```
Request → IP Blacklist Check → Regex Detection → ML Classifier → Allow/Block
```

1. **IP Blacklist**: Immediately blocks banned IPs
2. **Regex Engine**: 30+ patterns across 4 attack categories
3. **ML Fallback**: Naive Bayes with char n-gram TF-IDF catches obfuscated attacks

##  What Happens When an IP Is Blocked

- An IP gets **1 strike** each time malicious input is detected.
- After **5 strikes**, FlaskGuard auto-bans that IP.
- Auto-ban duration is **60 minutes**.
- While banned, every request from that IP is denied with **403 Access denied**.
- Expired bans are removed automatically on the next blacklist check.

You can manually unban an IP from the dashboard API:

```bash
curl -X POST http://localhost:5000/admin/api/unban \
    -H "Content-Type: application/json" \
    -d '{"ip":"127.0.0.1"}'
```

##  Test Attack Payloads

```bash
# SQL Injection
curl "http://localhost:5000/search?q=' OR 1=1 --"

# XSS
curl "http://localhost:5000/search?q=<script>alert(1)</script>"

# Path Traversal
curl "http://localhost:5000/search?q=../../etc/passwd"

# Command Injection
curl "http://localhost:5000/search?q=; ls -la"

# Normal request (should pass)
curl "http://localhost:5000/search?q=laptop"
```

##  Admin API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/admin` | GET | Dashboard UI |
| `/admin/api/stats` | GET | Attack statistics |
| `/admin/api/attacks` | GET | Recent attack log |
| `/admin/api/blacklist` | GET | Active blacklist |
| `/admin/api/ban` | POST | `{"ip": "x.x.x.x", "minutes": 60}` |
| `/admin/api/unban` | POST | `{"ip": "x.x.x.x"}` |
| `/admin/api/simulate` | POST | Seed demo attack data |

##  How It Compares to Real WAFs

| FlaskGuard | Enterprise WAF (Cloudflare/OWASP) |
|---|---|
| Regex + ML detection | Rule engines + ML + heuristics |
| Per-IP rate limiting | Global + per-IP + per-user |
| JSON log | SIEM integration |
| Manual blacklist | Threat intelligence feeds |

This is a **learning/portfolio project** demonstrating core WAF concepts.

