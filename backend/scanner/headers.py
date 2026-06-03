import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "cvss_score": 7.4,
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "cvss_score": 6.1,
        "recommendation": "Add Content-Security-Policy header to prevent XSS attacks."
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "cvss_score": 4.3,
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking."
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "cvss_score": 4.3,
        "recommendation": "Add: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "cvss_score": 3.1,
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "cvss_score": 3.1,
        "recommendation": "Add Permissions-Policy header to control browser features."
    }
}

def scan_headers(url, session=None):
    findings = []
    if not session:
        session = requests.Session()

    try:
        response = session.get(url, timeout=10)
        headers = response.headers

        for header, info in SECURITY_HEADERS.items():
            if header not in headers:
                findings.append({
                    "url": url,
                    "parameter": header,
                    "vulnerability_type": "SECURITY_HEADERS",
                    "severity": info["severity"],
                    "cvss_score": info["cvss_score"],
                    "payload": "N/A",
                    "evidence": f"Missing security header: {header}",
                    "recommendation": info["recommendation"]
                })

    except Exception as e:
        print(f"Headers scan error: {e}")

    return findings