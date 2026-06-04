import requests
from bs4 import BeautifulSoup

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "\" OR \"1\"=\"1",
    "'; DROP TABLE users; --",
    "' UNION SELECT NULL --",
    "' AND 1=2 UNION SELECT 1,2,3 --",
    "1' ORDER BY 1 --",
    "1' ORDER BY 2 --",
]

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "mysql_fetch",
    "mysql_num_rows",
    "ora-01756",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "sqlite_error",
    "pg_query",
    "postgresql",
]

def scan_sqli(url, session=None):
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
            for payload in SQLI_PAYLOADS:
                test_url = inject_param(url, param, payload)
                try:
                    res = session.get(test_url, timeout=10)
                    if is_vulnerable(res.text):
                        findings.append({
                            "url": test_url,
                            "parameter": param,
                            "vulnerability_type": "SQL_INJECTION",
                            "severity": "CRITICAL",
                            "cvss_score": 9.8,
                            "payload": payload,
                            "evidence": extract_evidence(res.text),
                            "recommendation": "Use prepared statements and parameterized queries. Never concatenate user input into SQL queries."
                        })
                        break
                except:
                    continue

        # Test form inputs
        for form in forms:
            form_findings = test_form(url, form, session)
            findings.extend(form_findings)

    except Exception as e:
        print(f"SQLi scan error: {e}")

    return findings


def test_form(url, form, session):
    findings = []
    action = form.get('action', url)
    method = form.get('method', 'get').lower()
    inputs = form.find_all('input')

    for payload in SQLI_PAYLOADS:
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

            if is_vulnerable(res.text):
                findings.append({
                    "url": url,
                    "parameter": str(list(data.keys())),
                    "vulnerability_type": "SQL_INJECTION",
                    "severity": "CRITICAL",
                    "cvss_score": 9.8,
                    "payload": payload,
                    "evidence": extract_evidence(res.text),
                    "recommendation": "Use prepared statements and parameterized queries."
                })
                break
        except:
            continue

    return findings


def is_vulnerable(response_text):
    text = response_text.lower()
    return any(error in text for error in SQL_ERRORS)


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
                    new_query.append(f"{key}={payload}")
                else:
                    new_query.append(p)
        return parts[0] + '?' + '&'.join(new_query)
    return url


def extract_evidence(text):
    for error in SQL_ERRORS:
        idx = text.lower().find(error)
        if idx != -1:
            return text[max(0, idx-50):idx+100]
    return "SQL error detected in response"