

from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from security import detect_attack
from ml_classifier import ml_detect, ml_confidence
from attack_logger import log_attack, get_recent, get_stats
from ip_manager import is_blacklisted, record_strike, manual_ban, unban, get_blacklist

app = Flask(__name__)
app.secret_key = "flaskguard-secret-change-in-production"

# Rate Limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Security Middleware

@app.before_request
def security_middleware():
    ip = request.remote_addr

    # Skip admin dashboard itself from being filtered
    if request.path.startswith("/admin") or request.path.startswith("/static"):
        return

    # Check IP blacklist first
    if is_blacklisted(ip):
        return jsonify({"error": "Access denied — IP blacklisted"}), 403

    # Collect all input data
    parts = []
    if request.args:
        parts.append(str(dict(request.args)))
    if request.form:
        parts.append(str(dict(request.form)))
    if request.is_json and request.json:
        parts.append(str(request.json))
    # Also check raw path
    parts.append(request.full_path)

    combined = " ".join(parts)

    if not combined.strip():
        return  # nothing to inspect

    # 1) Regex detection
    result = detect_attack(combined)
    detection_method = None
    category = None

    if result["malicious"]:
        detection_method = "Regex"
        category = result["category"]
    else:
        # 2) ML detection as second layer
        if ml_detect(combined):
            detection_method = "ML Classifier"
            category = "Suspicious Input"

    if detection_method:
        auto_banned = record_strike(ip)
        log_attack(
            ip=ip,
            method=request.method,
            path=request.path,
            user_agent=request.headers.get("User-Agent", ""),
            payload=combined[:300],
            category=category,
            detection_method=detection_method,
            auto_banned=auto_banned,
        )
        msg = "Malicious input detected"
        if auto_banned:
            msg += " — IP auto-banned"
        return jsonify({"error": msg, "category": category}), 403


# Demo Protected Routes

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    data = request.json or request.form
    username = data.get("username", "")
    password = data.get("password", "")
    # Demo — never actually validate
    return jsonify({"message": f"Login attempted for user: {username}"})


@app.route("/search", methods=["GET"])
def search():
    query = request.args.get("q", "")
    return jsonify({"results": f"Search results for: {query}", "count": 0})


@app.route("/profile", methods=["GET"])
def profile():
    user_id = request.args.get("id", "1")
    return jsonify({"user": {"id": user_id, "name": "Demo User", "role": "user"}})


@app.route("/comment", methods=["POST"])
def comment():
    data = request.json or {}
    text = data.get("text", "")
    return jsonify({"message": "Comment posted", "text": text})


# Admin Dashboard API

@app.route("/admin")
@limiter.exempt
def admin_dashboard():
    return render_template("dashboard.html")


@app.route("/admin/api/stats")
@limiter.exempt
def api_stats():
    return jsonify(get_stats())


@app.route("/admin/api/attacks")
@limiter.exempt
def api_attacks():
    limit = int(request.args.get("limit", 50))
    return jsonify(get_recent(limit))


@app.route("/admin/api/blacklist")
@limiter.exempt
def api_blacklist():
    return jsonify(get_blacklist())


@app.route("/admin/api/ban", methods=["POST"])
@limiter.exempt
def api_ban():
    data = request.json or {}
    ip = data.get("ip")
    minutes = int(data.get("minutes", 60))
    if not ip:
        return jsonify({"error": "IP required"}), 400
    manual_ban(ip, minutes)
    return jsonify({"message": f"Banned {ip} for {minutes} minutes"})


@app.route("/admin/api/unban", methods=["POST"])
@limiter.exempt
def api_unban():
    data = request.json or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP required"}), 400
    unban(ip)
    return jsonify({"message": f"Unbanned {ip}"})


# Test endpoint — fire fake attack events

@app.route("/admin/api/simulate", methods=["POST"])
@limiter.exempt
def simulate_attacks():
    """Seed some fake attack data for demo purposes."""
    import random
    from attack_logger import log_attack as _log

    fake_ips = ["192.168.1.10", "10.0.0.55", "172.16.0.3", "203.0.113.42"]
    fake_payloads = [
        ("' OR 1=1 --", "SQL Injection", "Regex"),
        ("UNION SELECT password FROM users", "SQL Injection", "Regex"),
        ("<script>alert('xss')</script>", "XSS", "Regex"),
        ("../../etc/passwd", "Path Traversal", "Regex"),
        ("; ls -la", "Command Injection", "Regex"),
        ("eval(atob('test'))", "XSS", "ML Classifier"),
        ("' AND SLEEP(5)--", "SQL Injection", "ML Classifier"),
    ]

    for _ in range(20):
        ip = random.choice(fake_ips)
        payload, cat, method = random.choice(fake_payloads)
        _log(ip=ip, method="POST", path="/login",
             user_agent="Mozilla/5.0 (attacker)", payload=payload,
             category=cat, detection_method=method, auto_banned=False)

    return jsonify({"message": "20 simulated attacks logged"})


if __name__ == "__main__":
    print("🛡  FlaskGuard WAF starting...")
    print("   App:       http://127.0.0.1:5000")
    print("   Dashboard: http://127.0.0.1:5000/admin")
    app.run(debug=True, port=5000)
