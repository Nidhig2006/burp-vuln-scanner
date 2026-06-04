from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
from dotenv import load_dotenv
import bcrypt
import os
import threading

from db import get_connection, init_db
from models import (
    create_user, get_user_by_username, get_user_by_id,
    update_last_login, create_scan, get_all_scans,
    get_scan_by_id, update_scan_status, create_finding,
    get_findings_by_scan, get_findings_summary,
    update_finding_status, create_report, get_reports_by_user
)
from scanner.sqli import scan_sqli
from scanner.xss import scan_xss
from scanner.headers import scan_headers
from scanner.sensitive import scan_sensitive
from scanner.redirect import scan_redirect
from scanner.info_disclosure import scan_info_disclosure

load_dotenv()

app = Flask(__name__)
CORS(app, origins="*")

app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET", "supersecretkey")
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ─── AUTH ROUTES ───────────────────────────────────────

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    role = data.get("role", "tester")

    if not username or not email or not password:
        return jsonify({"error": "All fields required"}), 400

    existing = get_user_by_username(username)
    if existing:
        return jsonify({"error": "Username already exists"}), 409

    password_hash = bcrypt.hashpw(
        password.encode('utf-8'),
        bcrypt.gensalt()
    ).decode('utf-8')

    user_id = create_user(username, email, password_hash, role)
    return jsonify({
        "message": "User registered successfully",
        "user_id": user_id
    }), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    if not bcrypt.checkpw(
        password.encode('utf-8'),
        user['password_hash'].encode('utf-8')
    ):
        return jsonify({"error": "Invalid credentials"}), 401

    update_last_login(user['id'])
    access_token = create_access_token(identity=str(user['id']))

    return jsonify({
        "access_token": access_token,
        "username": user['username'],
        "role": user['role']
    }), 200


# ─── SCAN ROUTES ───────────────────────────────────────

@app.route("/api/scans", methods=["GET"])
@jwt_required()
def get_scans():
    user_id = get_jwt_identity()
    scans = get_all_scans(user_id)
    return jsonify(scans), 200


@app.route("/api/scans/<int:scan_id>", methods=["GET"])
@jwt_required()
def get_scan(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan), 200


@app.route("/api/scans/start", methods=["POST"])
@jwt_required()
def start_scan():
    user_id = get_jwt_identity()
    data = request.get_json()
    target_url = data.get("target_url")
    scan_name = data.get("scan_name", f"Scan of {target_url}")

    if not target_url:
        return jsonify({"error": "Target URL required"}), 400

    scan_id = create_scan(user_id, target_url, scan_name)

    # Run scan in background thread
    thread = threading.Thread(
        target=run_full_scan,
        args=(scan_id, target_url)
    )
    thread.daemon = True
    thread.start()

    return jsonify({
        "message": "Scan started",
        "scan_id": scan_id
    }), 202


@app.route("/api/scans/<int:scan_id>/stop", methods=["POST"])
@jwt_required()
def stop_scan(scan_id):
    update_scan_status(scan_id, "stopped")
    return jsonify({"message": "Scan stopped"}), 200


# ─── FINDINGS ROUTES ───────────────────────────────────

@app.route("/api/scans/<int:scan_id>/findings", methods=["GET"])
@jwt_required()
def get_findings(scan_id):
    findings = get_findings_by_scan(scan_id)
    return jsonify(findings), 200


@app.route("/api/scans/<int:scan_id>/summary", methods=["GET"])
@jwt_required()
def get_summary(scan_id):
    summary = get_findings_summary(scan_id)
    return jsonify(summary), 200


@app.route("/api/findings/<int:finding_id>/status", methods=["PUT"])
@jwt_required()
def update_status(finding_id):
    data = request.get_json()
    status = data.get("status")
    update_finding_status(finding_id, status)
    return jsonify({"message": "Status updated"}), 200


# ─── REPORTS ROUTES ────────────────────────────────────

@app.route("/api/reports", methods=["GET"])
@jwt_required()
def get_reports():
    user_id = get_jwt_identity()
    reports = get_reports_by_user(user_id)
    return jsonify(reports), 200


@app.route("/api/reports/generate", methods=["POST"])
@jwt_required()
def generate_report():
    user_id = get_jwt_identity()
    data = request.get_json()
    scan_id = data.get("scan_id")
    format = data.get("format", "PDF")

    scan = get_scan_by_id(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    report_name = f"Report_{scan['target_url']}_{scan_id}"
    file_path = f"reports/{report_name}.{format.lower()}"

    report_id = create_report(
        scan_id, user_id,
        report_name, format, file_path
    )

    return jsonify({
        "message": "Report generated",
        "report_id": report_id,
        "file_path": file_path
    }), 201


# ─── FULL SCAN RUNNER ──────────────────────────────────

def run_full_scan(scan_id, target_url):
    import requests as req_lib
    session = req_lib.Session()
    session.headers.update({
        'User-Agent': 'BurpVulnScanner/1.0'
    })

    all_findings = []
    total = 0

    scanners = [
        ("Security Headers", scan_headers),
        ("SQL Injection",    scan_sqli),
        ("XSS",             scan_xss),
        ("Sensitive Data",   scan_sensitive),
        ("Open Redirect",    scan_redirect),
        ("Info Disclosure",  scan_info_disclosure),
    ]

    for name, scanner_fn in scanners:
        try:
            socketio.emit('scan_progress', {
                "scan_id": scan_id,
                "module": name,
                "status": "running"
            })

            findings = scanner_fn(target_url, session)

            for finding in findings:
                finding_id = create_finding(
                    scan_id,
                    finding["url"],
                    finding["parameter"],
                    finding["vulnerability_type"],
                    finding["severity"],
                    finding["cvss_score"],
                    finding["payload"],
                    finding["evidence"],
                    finding["recommendation"]
                )
                finding["id"] = finding_id
                all_findings.append(finding)
                total += 1

                # Emit each finding in real-time
                socketio.emit('new_finding', {
                    "scan_id": scan_id,
                    "finding": finding
                })

        except Exception as e:
            print(f"Error in {name} scanner: {e}")
            continue

    # Mark scan complete
    update_scan_status(scan_id, "completed", total)
    socketio.emit('scan_complete', {
        "scan_id": scan_id,
        "total_findings": total
    })


# ─── WEBSOCKET EVENTS ──────────────────────────────────

@socketio.on('connect')
def on_connect():
    print(f"Client connected: {request.sid}")
    emit('connected', {"message": "Connected to VulnScanner"})


@socketio.on('disconnect')
def on_disconnect():
    print(f"Client disconnected: {request.sid}")


@socketio.on('join_scan')
def on_join_scan(data):
    scan_id = data.get('scan_id')
    emit('joined', {"scan_id": scan_id})


# ─── HEALTH CHECK ──────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "running",
        "message": "VulnScanner API is up"
    }), 200


# ─── START SERVER ──────────────────────────────────────

# ─── BURP EXTENSION ROUTE ──────────────────────────────

@app.route("/api/burp/finding", methods=["POST"])
def burp_finding():
    data = request.get_json()
    
    # Get or create a burp scan session
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Find active burp scan or create one
    cursor.execute(
        """SELECT id FROM scans WHERE scan_name = 'Burp Suite Live Scan' 
        AND status = 'running' ORDER BY started_at DESC LIMIT 1"""
    )
    scan = cursor.fetchone()
    
    if not scan:
        cursor.execute(
            """INSERT INTO scans (user_id, target_url, scan_name, status) 
            VALUES (1, %s, 'Burp Suite Live Scan', 'running')""",
            (data.get('url', 'unknown'),)
        )
        conn.commit()
        scan_id = cursor.lastrowid
    else:
        scan_id = scan['id']
    
    cursor.close()
    conn.close()

    finding_id = create_finding(
        scan_id,
        data.get('url', ''),
        data.get('parameter', ''),
        data.get('vulnerability_type', 'INFO_DISCLOSURE'),
        data.get('severity', 'LOW'),
        data.get('cvss_score', 0.0),
        'Burp Passive Scan',
        data.get('parameter', ''),
        'Review and fix this vulnerability'
    )

    socketio.emit('new_finding', {
        "scan_id": scan_id,
        "finding": data
    })

    return jsonify({"message": "Finding saved", "id": finding_id}), 201


if __name__ == "__main__":
    init_db()
    socketio.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("FLASK_PORT", 5000)),
        debug=True
    )