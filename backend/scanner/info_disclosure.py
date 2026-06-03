import requests

SENSITIVE_PATHS = [
    "/.git/config",
    "/.env",
    "/config.php",
    "/wp-config.php",
    "/admin",
    "/phpmyadmin",
    "/server-status",
    "/.htaccess",
    "/backup.sql",
    "/database.sql",
    "/config.json",
    "/api/config",
]

SERVER_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]

def scan_info_disclosure(url, session=None):
    findings = []
    if not session:
        session = requests.Session()

    base_url = url.rstrip('/')

    # Check sensitive paths
    for path in SENSITIVE_PATHS:
        try:
            res = session.get(base_url + path, timeout=10)
            if res.status_code == 200:
                findings.append({
                    "url": base_url + path,
                    "parameter": path,
                    "vulnerability_type": "INFO_DISCLOSURE",
                    "severity": "HIGH",
                    "cvss_score": 7.5,
                    "payload": "N/A",
                    "evidence": f"Sensitive path accessible: {path} (Status: 200)",
                    "recommendation": f"Restrict access to {path}. Remove sensitive files from web root."
                })
        except:
            continue

    # Check server version disclosure in headers
    try:
        res = session.get(url, timeout=10)
        for header in SERVER_HEADERS:
            if header in res.headers:
                findings.append({
                    "url": url,
                    "parameter": header,
                    "vulnerability_type": "INFO_DISCLOSURE",
                    "severity": "LOW",
                    "cvss_score": 3.1,
                    "payload": "N/A",
                    "evidence": f"{header}: {res.headers[header]}",
                    "recommendation": f"Remove or obscure the {header} header to prevent version disclosure."
                })
    except:
        pass

    return findings