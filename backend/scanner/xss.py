import requests
from bs4 import BeautifulSoup
import urllib.parse

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "'><script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "<iframe src=javascript:alert('XSS')>",
]

def scan_xss(url, session=None):
    findings = []
    if not session:
        session = requests.Session()

    try:
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        params = extract_params(url)

        # Test URL parameters
        for param in params:
            for payload in XSS_PAYLOADS:
                test_url = inject_param(url, param, payload)
                try:
                    res = session.get(test_url, timeout=10)
                    if is_vulnerable(res.text, payload):
                        findings.append({
                            "url": test_url,
                            "parameter": param,
                            "vulnerability_type": "XSS",
                            "severity": "HIGH",
                            "cvss_score": 7.4,
                            "payload": payload,
                            "evidence": f"Payload reflected in response: {payload[:50]}",
                            "recommendation": "Encode all user input before rendering in HTML. Use Content-Security-Policy headers."
                        })
                        break
                except:
                    continue

        # Test forms
        for form in forms:
            form_findings = test_form_xss(url, form, session)
            findings.extend(form_findings)

    except Exception as e:
        print(f"XSS scan error: {e}")

    return findings


def test_form_xss(url, form, session):
    findings = []
    method = form.get('method', 'get').lower()
    inputs = form.find_all('input')

    for payload in XSS_PAYLOADS:
        data = {}
        for input_tag in inputs:
            name = input_tag.get('name', '')
            if name:
                data[name] = payload

        try:
            if method == 'post':
                res = session.post(url, data=data, timeout=10)
            else:
                res = session.get(url, params=data, timeout=10)

            if is_vulnerable(res.text, payload):
                findings.append({
                    "url": url,
                    "parameter": str(list(data.keys())),
                    "vulnerability_type": "XSS",
                    "severity": "HIGH",
                    "cvss_score": 7.4,
                    "payload": payload,
                    "evidence": f"Payload reflected in response",
                    "recommendation": "Sanitize and encode user input. Implement CSP headers."
                })
                break
        except:
            continue

    return findings


def is_vulnerable(response_text, payload):
    return payload in response_text or urllib.parse.quote(payload) in response_text


def extract_params(url):
    params = []
    if '?' in url:
        query = url.split('?')[1]
        for param in query.split('&'):
            if '=' in param:
                params.append(param.split('=')[0])
    return params


def inject_param(url, param, payload):
    if '?' in url:
        parts = url.split('?')
        query = parts[1]
        new_query = []
        for p in query.split('&'):
            if '=' in p:
                key, val = p.split('=', 1)
                if key == param:
                    new_query.append(f"{key}={urllib.parse.quote(payload)}")
                else:
                    new_query.append(p)
        return parts[0] + '?' + '&'.join(new_query)
    return url