from db import get_connection
from datetime import datetime

# ─── USER MODELS ───────────────────────────────────────

def create_user(username, email, password_hash, role='tester'):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, email, password_hash, role) VALUES (%s, %s, %s, %s)",
        (username, email, password_hash, role)
    )
    conn.commit()
    user_id = cursor.lastrowid
    cursor.close()
    conn.close()
    return user_id

def get_user_by_username(username):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user

def get_user_by_id(user_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user

def update_last_login(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET last_login = %s WHERE id = %s",
        (datetime.now(), user_id)
    )
    conn.commit()
    cursor.close()
    conn.close()

# ─── SCAN MODELS ───────────────────────────────────────

def create_scan(user_id, target_url, scan_name):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans (user_id, target_url, scan_name) VALUES (%s, %s, %s)",
        (user_id, target_url, scan_name)
    )
    conn.commit()
    scan_id = cursor.lastrowid
    cursor.close()
    conn.close()
    return scan_id

def get_all_scans(user_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM scans WHERE user_id = %s ORDER BY started_at DESC",
        (user_id,)
    )
    scans = cursor.fetchall()
    cursor.close()
    conn.close()
    return scans

def get_scan_by_id(scan_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM scans WHERE id = %s", (scan_id,))
    scan = cursor.fetchone()
    cursor.close()
    conn.close()
    return scan

def update_scan_status(scan_id, status, total_findings=0):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """UPDATE scans SET status = %s, total_findings = %s, 
        completed_at = %s WHERE id = %s""",
        (status, total_findings, datetime.now(), scan_id)
    )
    conn.commit()
    cursor.close()
    conn.close()

# ─── FINDINGS MODELS ───────────────────────────────────

def create_finding(scan_id, url, parameter, vuln_type, 
                   severity, cvss_score, payload, evidence, recommendation):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO findings 
        (scan_id, url, parameter, vulnerability_type, severity, 
        cvss_score, payload, evidence, recommendation)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (scan_id, url, parameter, vuln_type, severity,
         cvss_score, payload, evidence, recommendation)
    )
    conn.commit()
    finding_id = cursor.lastrowid
    cursor.close()
    conn.close()
    return finding_id

def get_findings_by_scan(scan_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM findings WHERE scan_id = %s ORDER BY severity",
        (scan_id,)
    )
    findings = cursor.fetchall()
    cursor.close()
    conn.close()
    return findings

def get_findings_summary(scan_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        """SELECT severity, COUNT(*) as count 
        FROM findings WHERE scan_id = %s 
        GROUP BY severity""",
        (scan_id,)
    )
    summary = cursor.fetchall()
    cursor.close()
    conn.close()
    return summary

def update_finding_status(finding_id, status):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE findings SET status = %s WHERE id = %s",
        (status, finding_id)
    )
    conn.commit()
    cursor.close()
    conn.close()

# ─── HTTP LOG MODELS ───────────────────────────────────

def create_http_log(scan_id, finding_id, method, url,
                    req_headers, req_body, res_code, res_headers, res_body):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO http_logs 
        (scan_id, finding_id, method, url, request_headers, 
        request_body, response_code, response_headers, response_body)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (scan_id, finding_id, method, url, req_headers,
         req_body, res_code, res_headers, res_body)
    )
    conn.commit()
    cursor.close()
    conn.close()

# ─── REPORT MODELS ─────────────────────────────────────

def create_report(scan_id, user_id, report_name, format, file_path):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO reports 
        (scan_id, user_id, report_name, format, file_path)
        VALUES (%s, %s, %s, %s, %s)""",
        (scan_id, user_id, report_name, format, file_path)
    )
    conn.commit()
    report_id = cursor.lastrowid
    cursor.close()
    conn.close()
    return report_id

def get_reports_by_user(user_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        """SELECT r.*, s.target_url FROM reports r 
        JOIN scans s ON r.scan_id = s.id 
        WHERE r.user_id = %s ORDER BY r.generated_at DESC""",
        (user_id,)
    )
    reports = cursor.fetchall()
    cursor.close()
    conn.close()
    return reports
