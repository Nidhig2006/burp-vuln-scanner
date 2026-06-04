import requests
import re

SENSITIVE_PATTERNS = {
    "AWS_ACCESS_KEY": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "CRITICAL",
        "cvss_score": 9.8
    },
    "AWS_SECRET_KEY": {
        "pattern": r"[0-9a-zA-Z/+]{40}",
        "severity": "CRITICAL",
        "cvss_score": 9.8
    },
    "JWT_TOKEN": {
        "pattern": r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
        "severity": "HIGH",
        "cvss_score": 7.5
    },
    "PRIVATE_IP": {
        "pattern": r"(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)\d+\.\d+",
        "severity": "MEDIUM",
        "cvss_score": 5.3
    },
    "EMAIL_ADDRESS": {
        "pattern": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "severity": "LOW",
        "cvss_score": 3.1
    },
    "GOOGLE_API_KEY": {
        "pattern": r"AIza[0-9A-Za-z\\-_]{35}",
        "severity": "CRITICAL",
        "cvss_score": 9.8
    },
    "PRIVATE_KEY": {
        "pattern": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
        "severity": "CRITICAL",
        "cvss_score": 9.8
    },
    "PASSWORD_IN_URL": {
        "pattern": r"[?&]password=[^&]+",
        "severity": "HIGH",
        "cvss_score": 7.5
    },
}

def scan_sensitive(url, session=None):
    findings = []
    if not session:
        session = requests.Session()

    try:
        response = session.get(url, timeout=10)
        content = response.text

        for data_type, info in SENSITIVE_PATTERNS.items():
            matches = re.findall(info["pattern"], content)
            if matches:
                findings.append({
                    "url": url,
                    "parameter": data_type,
                    "vulnerability_type": "SENSITIVE_DATA",
                    "severity": info["severity"],
                    "cvss_score": info["cvss_score"],
                    "payload": "N/A",
                    "evidence": f"Found {data_type}: {str(matches[0])[:50]}",
                    "recommendation": f"Remove {data_type} from source code and rotate credentials immediately."
                })

    except Exception as e:
        print(f"Sensitive data scan error: {e}")

    return findings