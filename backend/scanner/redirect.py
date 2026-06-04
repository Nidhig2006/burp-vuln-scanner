import requests

REDIRECT_PARAMS = [
    "redirect", "url", "next", "return",
    "returnUrl", "redirect_uri", "callback",
    "goto", "dest", "destination", "redir"
]

EXTERNAL_TEST_URL = "https://evil.com"

def scan_redirect(url, session=None):
    findings = []
    if not session:
        session = requests.Session()

    try:
        for param in REDIRECT_PARAMS:
            test_url = f"{url}?{param}={EXTERNAL_TEST_URL}"
            try:
                res = session.get(
                    test_url,
                    timeout=10,
                    allow_redirects=False
                )
                if res.status_code in [301, 302, 303, 307, 308]:
                    location = res.headers.get('Location', '')
                    if 'evil.com' in location:
                        findings.append({
                            "url": test_url,
                            "parameter": param,
                            "vulnerability_type": "OPEN_REDIRECT",
                            "severity": "MEDIUM",
                            "cvss_score": 6.1,
                            "payload": EXTERNAL_TEST_URL,
                            "evidence": f"Redirects to: {location}",
                            "recommendation": "Validate and whitelist redirect URLs. Never redirect to user-supplied URLs directly."
                        })
            except:
                continue

    except Exception as e:
        print(f"Redirect scan error: {e}")

    return findings