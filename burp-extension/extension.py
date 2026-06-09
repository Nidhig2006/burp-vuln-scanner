# -*- coding: utf-8 -*-
# VulnScanner Pro - Professional Burp Suite Extension
# Language: Jython (Python 2.7)

from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import (JPanel, JScrollPane, JTable, JButton,
                          JLabel, JTextArea, JSplitPane, JTabbedPane)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, Color, Font, Dimension
import json
import re
import urllib2
import hashlib
from datetime import datetime
from collections import defaultdict

# ── CONSTANTS ─────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# CWE and OWASP mappings
VULN_META = {
    "MISSING_HSTS": {
        "cwe": "CWE-319",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "MEDIUM",
        "confidence": "Certain",
        "cvss": 5.3,
    },
    "MISSING_CSP": {
        "cwe": "CWE-1021",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "MEDIUM",
        "confidence": "Certain",
        "cvss": 4.3,
    },
    "MISSING_XFRAME": {
        "cwe": "CWE-1021",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "LOW",
        "confidence": "Certain",
        "cvss": 3.1,
    },
    "MISSING_XCTO": {
        "cwe": "CWE-430",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "LOW",
        "confidence": "Certain",
        "cvss": 3.1,
    },
    "SERVER_BANNER": {
        "cwe": "CWE-200",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "LOW",
        "confidence": "Certain",
        "cvss": 2.7,
    },
    "SQL_INJECTION": {
        "cwe": "CWE-89",
        "owasp": "A03:2021 Injection",
        "severity": "CRITICAL",
        "confidence": "Firm",
        "cvss": 9.8,
    },
    "XSS": {
        "cwe": "CWE-79",
        "owasp": "A03:2021 Injection",
        "severity": "HIGH",
        "confidence": "Firm",
        "cvss": 7.4,
    },
    "CORS_MISCONFIGURATION": {
        "cwe": "CWE-942",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "HIGH",
        "confidence": "Certain",
        "cvss": 7.4,
    },
    "INSECURE_COOKIE": {
        "cwe": "CWE-614",
        "owasp": "A02:2021 Cryptographic Failures",
        "severity": "MEDIUM",
        "confidence": "Certain",
        "cvss": 5.3,
    },
    "SENSITIVE_DATA": {
        "cwe": "CWE-312",
        "owasp": "A02:2021 Cryptographic Failures",
        "severity": "CRITICAL",
        "confidence": "Certain",
        "cvss": 9.8,
    },
    "JWT_WEAKNESS": {
        "cwe": "CWE-347",
        "owasp": "A02:2021 Cryptographic Failures",
        "severity": "HIGH",
        "confidence": "Firm",
        "cvss": 7.5,
    },
    "OPEN_REDIRECT": {
        "cwe": "CWE-601",
        "owasp": "A01:2021 Broken Access Control",
        "severity": "MEDIUM",
        "confidence": "Firm",
        "cvss": 6.1,
    },
    "INFO_DISCLOSURE": {
        "cwe": "CWE-200",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "LOW",
        "confidence": "Firm",
        "cvss": 3.1,
    },
    "EXPOSED_FILE": {
        "cwe": "CWE-538",
        "owasp": "A05:2021 Security Misconfiguration",
        "severity": "HIGH",
        "confidence": "Certain",
        "cvss": 7.5,
    },
    "RATE_LIMIT": {
        "cwe": "CWE-770",
        "owasp": "A04:2021 Insecure Design",
        "severity": "MEDIUM",
        "confidence": "Tentative",
        "cvss": 5.3,
    },
}


class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName("VulnScanner Pro")

        self._tableModel = DefaultTableModel(
            ["Sev", "Conf", "Type", "Evidence", "Domain", "CWE", "CVSS"], 0
        )
        self._findings        = []
        self._seen_hashes     = set()
        self._domain_findings = defaultdict(list)
        self._request_counts  = defaultdict(int)
        self._count           = 0

        self._panel = self.buildUI()
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)

        print("[VulnScanner Pro] Loaded! Dashboard: http://localhost:5173")

    def getTabCaption(self):
        return "VulnScanner Pro"

    def getUiComponent(self):
        return self._panel

    # ── CONTEXT DETECTION ─────────────────────────────

    def getContentType(self, resHeaders):
        for h in resHeaders:
            if h.lower().startswith("content-type:"):
                return h.lower()
        return ""

    def isHTMLPage(self, url, resHeaders):
        ct = self.getContentType(resHeaders)
        return "text/html" in ct

    def isAPIEndpoint(self, url, resHeaders):
        ct = self.getContentType(resHeaders)
        urlLower = url.lower()
        apiSignals = [
            "/api/", "/v1/", "/v2/", "/v3/",
            "/graphql", "/rest/", "/ws/",
            "application/json" in ct,
            "application/xml" in ct,
        ]
        return any(
            (s if isinstance(s, bool) else s in urlLower)
            for s in apiSignals
        )

    def isStaticAsset(self, url):
        urlLower = url.lower().split("?")[0]
        extensions = [
            ".js", ".css", ".png", ".jpg", ".jpeg",
            ".gif", ".svg", ".ico", ".woff", ".woff2",
            ".ttf", ".eot", ".mp4", ".mp3", ".pdf"
        ]
        return any(urlLower.endswith(ext) for ext in extensions)

    def isTelemetryEndpoint(self, url):
        telemetry = [
            "analytics", "telemetry", "tracking",
            "beacon", "metrics", "rum", "datadog",
            "newrelic", "sentry", "mixpanel",
            "google-analytics", "gtm", "hotjar"
        ]
        urlLower = url.lower()
        return any(t in urlLower for t in telemetry)

    def getDomain(self, url):
        try:
            parts = url.split("/")
            if len(parts) >= 3:
                return parts[2].split(":")[0]
        except:
            pass
        return url

    # ── DEDUPLICATION ─────────────────────────────────

    def isDuplicate(self, domain, vulnType, evidence):
        key = domain + "|" + vulnType + "|" + evidence[:40]
        h = hashlib.md5(key.encode("utf-8")).hexdigest()
        if h in self._seen_hashes:
            return True
        self._seen_hashes.add(h)
        return False

    # ── HTTP LISTENER ─────────────────────────────────

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        try:
            analyzedReq  = self._helpers.analyzeRequest(messageInfo)
            analyzedRes  = self._helpers.analyzeResponse(
                messageInfo.getResponse()
            )
            url        = str(analyzedReq.getUrl())
            method     = analyzedReq.getMethod()
            resHeaders = analyzedRes.getHeaders()
            resBody    = self._helpers.bytesToString(
                messageInfo.getResponse()
            )
            reqHeaders = analyzedReq.getHeaders()
            statusCode = analyzedRes.getStatusCode()
            domain     = self.getDomain(url)

            # Skip static assets and telemetry
            if self.isStaticAsset(url):
                return
            if self.isTelemetryEndpoint(url):
                return

            # Track request count per domain for rate limit check
            self._request_counts[domain] += 1

            isHTML = self.isHTMLPage(url, resHeaders)
            isAPI  = self.isAPIEndpoint(url, resHeaders)

            # Context-aware checks
            if isHTML:
                self.checkSecurityHeaders(url, domain, resHeaders,
                                          statusCode, method)
                self.checkClickjacking(url, domain, resHeaders,
                                       statusCode, method)

            self.checkCORSMisconfiguration(url, domain, reqHeaders,
                                           resHeaders, statusCode, method)
            self.checkInsecureCookies(url, domain, resHeaders,
                                      statusCode, method)
            self.checkSQLErrors(url, domain, resBody, statusCode, method)
            self.checkXSSReflection(url, domain, resBody, statusCode, method)
            self.checkSensitiveData(url, domain, resBody, statusCode, method)
            self.checkJWTWeakness(url, domain, resBody,
                                  resHeaders, statusCode, method)
            self.checkInfoDisclosure(url, domain, resBody,
                                     resHeaders, statusCode, method)
            self.checkOpenRedirect(url, domain, statusCode,
                                   resHeaders, method)
            self.checkExposedFiles(url, domain, statusCode, method)
            self.checkRateLimit(url, domain, resHeaders, statusCode, method)

        except Exception as e:
            print("[VulnScanner Pro] Error: " + str(e))

    # ── SECURITY HEADERS (HTML pages only) ────────────

    def checkSecurityHeaders(self, url, domain, resHeaders,
                              statusCode, method):
        headerNames = [h.split(":")[0].lower() for h in resHeaders]

        checks = [
            (
                "strict-transport-security",
                "MISSING_HSTS",
                "Missing HSTS (Strict-Transport-Security) header",
                "Users can be downgraded from HTTPS to HTTP enabling MITM attacks",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            ),
            (
                "content-security-policy",
                "MISSING_CSP",
                "Missing CSP (Content-Security-Policy) header",
                "No protection against XSS and data injection attacks",
                "Define a strict CSP policy restricting script/style sources"
            ),
            (
                "x-content-type-options",
                "MISSING_XCTO",
                "Missing X-Content-Type-Options header",
                "Browser may MIME-sniff responses leading to XSS",
                "Add: X-Content-Type-Options: nosniff"
            ),
        ]

        for (header, vuln_key, evidence, impact, fix) in checks:
            if header not in headerNames:
                meta = VULN_META[vuln_key]
                if not self.isDuplicate(domain, vuln_key, evidence):
                    self.addFinding(
                        url, domain, vuln_key,
                        meta["severity"], meta["confidence"],
                        meta["cvss"], meta["cwe"], meta["owasp"],
                        evidence, impact, fix,
                        statusCode, method
                    )

    def checkClickjacking(self, url, domain, resHeaders,
                          statusCode, method):
        headerNames = [h.split(":")[0].lower() for h in resHeaders]
        if ("x-frame-options" not in headerNames and
                "content-security-policy" not in headerNames):
            meta = VULN_META["MISSING_XFRAME"]
            evidence = "Missing X-Frame-Options and no CSP frame-ancestors directive"
            if not self.isDuplicate(domain, "MISSING_XFRAME", evidence):
                self.addFinding(
                    url, domain, "MISSING_XFRAME",
                    meta["severity"], meta["confidence"],
                    meta["cvss"], meta["cwe"], meta["owasp"],
                    evidence,
                    "Page can be embedded in iframes enabling Clickjacking",
                    "Add: X-Frame-Options: DENY or CSP frame-ancestors 'none'",
                    statusCode, method
                )

    # ── CORS MISCONFIGURATION ─────────────────────────

    def checkCORSMisconfiguration(self, url, domain, reqHeaders,
                                   resHeaders, statusCode, method):
        headerDict = {}
        for h in resHeaders:
            if ":" in h:
                k, v = h.split(":", 1)
                headerDict[k.lower().strip()] = v.strip()

        acao = headerDict.get("access-control-allow-origin", "")
        acac = headerDict.get("access-control-allow-credentials", "")

        if acao == "*" and acac.lower() == "true":
            evidence = ("CORS: Access-Control-Allow-Origin: * with "
                        "Allow-Credentials: true")
            meta = VULN_META["CORS_MISCONFIGURATION"]
            if not self.isDuplicate(domain, "CORS_MISCONFIGURATION", evidence):
                self.addFinding(
                    url, domain, "CORS_MISCONFIGURATION",
                    meta["severity"], meta["confidence"],
                    meta["cvss"], meta["cwe"], meta["owasp"],
                    evidence,
                    "Attacker can make authenticated cross-origin requests stealing user data",
                    "Never combine wildcard CORS with Allow-Credentials",
                    statusCode, method
                )
        elif acao == "*":
            evidence = "CORS: Access-Control-Allow-Origin: * (wildcard)"
            meta = VULN_META["CORS_MISCONFIGURATION"]
            if not self.isDuplicate(domain, "CORS_MISCONFIGURATION", evidence):
                self.addFinding(
                    url, domain, "CORS_MISCONFIGURATION",
                    "LOW", "Certain", 3.1,
                    meta["cwe"], meta["owasp"],
                    evidence,
                    "Any origin can read responses from this endpoint",
                    "Restrict CORS to specific trusted origins",
                    statusCode, method
                )

    # ── INSECURE COOKIES ──────────────────────────────

    def checkInsecureCookies(self, url, domain, resHeaders,
                              statusCode, method):
        for h in resHeaders:
            if h.lower().startswith("set-cookie:"):
                cookie = h[11:].strip()
                cookieLower = cookie.lower()
                cookieName  = cookie.split("=")[0].strip()

                issues = []
                if "secure" not in cookieLower:
                    issues.append("missing Secure flag")
                if "httponly" not in cookieLower:
                    issues.append("missing HttpOnly flag")
                if "samesite" not in cookieLower:
                    issues.append("missing SameSite attribute")

                if issues:
                    evidence = ("Insecure cookie [" + cookieName +
                                "]: " + ", ".join(issues))
                    meta = VULN_META["INSECURE_COOKIE"]
                    if not self.isDuplicate(domain,
                                            "INSECURE_COOKIE", evidence):
                        self.addFinding(
                            url, domain, "INSECURE_COOKIE",
                            meta["severity"], meta["confidence"],
                            meta["cvss"], meta["cwe"], meta["owasp"],
                            evidence,
                            "Cookie can be stolen via XSS or network interception",
                            "Add Secure; HttpOnly; SameSite=Strict to all cookies",
                            statusCode, method
                        )

    # ── SQL INJECTION ─────────────────────────────────

    def checkSQLErrors(self, url, domain, resBody, statusCode, method):
        sqlErrors = [
            ("you have an error in your sql syntax",
             "MySQL syntax error exposed - exact query structure visible",
             "Certain"),
            ("warning: mysql_",
             "MySQL function warning exposed in response",
             "Certain"),
            ("unclosed quotation mark after the character string",
             "MSSQL unclosed quote error - SQL Injection confirmed",
             "Certain"),
            ("ora-0",
             "Oracle database error exposed in response",
             "Certain"),
            ("microsoft ole db provider for sql server",
             "MSSQL OLE DB error - SQL Server details exposed",
             "Certain"),
            ("pg_query(): query failed",
             "PostgreSQL query error exposed in response",
             "Certain"),
            ("sqlite3.operationalerror",
             "SQLite error exposed in response",
             "Certain"),
            ("supplied argument is not a valid mysql",
             "MySQL argument error - possible injection point",
             "Firm"),
        ]

        meta = VULN_META["SQL_INJECTION"]
        for (pattern, evidence, confidence) in sqlErrors:
            if pattern.lower() in resBody.lower():
                if not self.isDuplicate(domain, "SQL_INJECTION", evidence):
                    self.addFinding(
                        url, domain, "SQL_INJECTION",
                        meta["severity"], confidence,
                        meta["cvss"], meta["cwe"], meta["owasp"],
                        evidence,
                        "SQL injection likely exploitable - database compromise possible",
                        "Use prepared statements and parameterized queries",
                        statusCode, method
                    )
                break

    # ── XSS DETECTION ────────────────────────────────

    def checkXSSReflection(self, url, domain, resBody,
                            statusCode, method):
        urlLower  = url.lower()
        bodyLower = resBody.lower()

        payloads = [
            ("<script>alert",
             "Script-based XSS payload reflected unescaped",
             "Firm"),
            ("onerror=alert",
             "Event handler XSS payload reflected in response",
             "Firm"),
            ("<img src=x onerror",
             "Image onerror XSS payload reflected in response",
             "Firm"),
            ("<svg/onload",
             "SVG onload XSS payload reflected in response",
             "Firm"),
            ("javascript:alert",
             "JavaScript protocol XSS reflected in response",
             "Tentative"),
        ]

        meta = VULN_META["XSS"]
        for (payload, evidence, confidence) in payloads:
            if payload in urlLower and payload in bodyLower:
                if not self.isDuplicate(domain, "XSS", evidence):
                    self.addFinding(
                        url, domain, "XSS",
                        meta["severity"], confidence,
                        meta["cvss"], meta["cwe"], meta["owasp"],
                        evidence,
                        "Attacker can execute scripts in victim browser stealing sessions/cookies",
                        "HTML-encode all user input. Implement strict CSP",
                        statusCode, method
                    )
                break

    # ── SENSITIVE DATA ────────────────────────────────

    def checkSensitiveData(self, url, domain, resBody,
                            statusCode, method):
        patterns = [
            (
                r"AKIA[0-9A-Z]{16}",
                "AWS Access Key ID exposed in response body",
                "CRITICAL", "Certain", 9.8,
                "Full AWS account compromise possible",
                "Rotate key immediately. Use IAM roles instead"
            ),
            (
                r"-----BEGIN (RSA )?PRIVATE KEY-----",
                "RSA Private Key exposed in response",
                "CRITICAL", "Certain", 9.8,
                "SSL/SSH private key compromise - all encrypted traffic at risk",
                "Remove immediately. Revoke and regenerate certificate"
            ),
            (
                r"AIza[0-9A-Za-z\-_]{35}",
                "Google API Key exposed in response body",
                "HIGH", "Certain", 7.5,
                "Unauthorized API usage and billing fraud possible",
                "Restrict key in Google Console. Rotate immediately"
            ),
            (
                r"[?&]password=[^&\s]{3,}",
                "Password transmitted as URL parameter",
                "HIGH", "Certain", 7.5,
                "Credentials in browser history, server logs, and referrer headers",
                "Use POST body for credentials. Never pass passwords in URLs"
            ),
            (
                r"Bearer [a-zA-Z0-9\-._~+/]{20,}",
                "Bearer token exposed in response body",
                "HIGH", "Firm", 7.5,
                "Authentication token can be stolen and reused for account takeover",
                "Never expose tokens in response bodies. Use secure storage"
            ),
        ]

        meta = VULN_META["SENSITIVE_DATA"]
        for (pattern, evidence, severity,
             confidence, cvss, impact, fix) in patterns:
            match = re.search(pattern, resBody)
            if match:
                matched = match.group(0)[:20] + "..."
                full_evidence = evidence + " [" + matched + "]"
                if not self.isDuplicate(domain, "SENSITIVE_DATA", evidence):
                    self.addFinding(
                        url, domain, "SENSITIVE_DATA",
                        severity, confidence,
                        cvss, meta["cwe"], meta["owasp"],
                        full_evidence, impact, fix,
                        statusCode, method
                    )

    # ── JWT WEAKNESS ──────────────────────────────────

    def checkJWTWeakness(self, url, domain, resBody,
                          resHeaders, statusCode, method):
        jwtPattern = (r"eyJ[a-zA-Z0-9_-]{10,}"
                      r"\.[a-zA-Z0-9_-]{10,}"
                      r"\.[a-zA-Z0-9_-]{0,}")
        match = re.search(jwtPattern, resBody)
        if not match:
            return

        token = match.group(0)
        parts = token.split(".")

        if len(parts) == 3:
            # Check for none algorithm (alg:none)
            try:
                import base64
                header_padded = (parts[0] +
                                 "=" * (4 - len(parts[0]) % 4))
                header = base64.b64decode(header_padded)
                if "none" in header.lower():
                    evidence = "JWT using alg:none - signature not verified"
                    meta = VULN_META["JWT_WEAKNESS"]
                    if not self.isDuplicate(domain,
                                            "JWT_WEAKNESS", evidence):
                        self.addFinding(
                            url, domain, "JWT_WEAKNESS",
                            "CRITICAL", "Certain", 9.8,
                            meta["cwe"], meta["owasp"],
                            evidence,
                            "JWT signature bypass - authentication can be forged",
                            "Never accept alg:none. Always verify signatures",
                            statusCode, method
                        )
                    return
            except:
                pass

            # Unsigned JWT (empty signature)
            if parts[2] == "":
                evidence = "JWT with empty signature exposed"
                meta = VULN_META["JWT_WEAKNESS"]
                if not self.isDuplicate(domain, "JWT_WEAKNESS", evidence):
                    self.addFinding(
                        url, domain, "JWT_WEAKNESS",
                        meta["severity"], meta["confidence"],
                        meta["cvss"], meta["cwe"], meta["owasp"],
                        evidence,
                        "Unsigned JWT accepted - authentication bypass possible",
                        "Enforce signature verification on all JWT tokens",
                        statusCode, method
                    )

    # ── INFO DISCLOSURE ───────────────────────────────

    def checkInfoDisclosure(self, url, domain, resBody,
                             resHeaders, statusCode, method):
        headerDict = {}
        for h in resHeaders:
            if ":" in h:
                k, v = h.split(":", 1)
                headerDict[k.lower().strip()] = v.strip()

        serverHeaders = {
            "server":           "Web server and version",
            "x-powered-by":     "Backend technology and version",
            "x-aspnet-version": ".NET framework version",
            "x-generator":      "CMS or framework name",
        }

        meta = VULN_META["SERVER_BANNER"]
        for h, desc in serverHeaders.items():
            if h in headerDict:
                evidence = (desc + " disclosed: " +
                            h + ": " + headerDict[h])
                if not self.isDuplicate(domain,
                                        "SERVER_BANNER", evidence):
                    self.addFinding(
                        url, domain, "SERVER_BANNER",
                        meta["severity"], meta["confidence"],
                        meta["cvss"], meta["cwe"], meta["owasp"],
                        evidence,
                        "Attacker fingerprints server to find version-specific CVEs",
                        "Remove or genericize server banner headers",
                        statusCode, method
                    )

        errorPatterns = {
            "stack trace":  "Stack trace in response body",
            "traceback":    "Python traceback in response body",
            "mysql_fetch":  "MySQL function name in response",
            "fatal error":  "PHP fatal error in response",
            "at java.":     "Java exception in response body",
        }

        meta = VULN_META["INFO_DISCLOSURE"]
        for pattern, evidence in errorPatterns.items():
            if pattern.lower() in resBody.lower():
                if not self.isDuplicate(domain,
                                        "INFO_DISCLOSURE", evidence):
                    self.addFinding(
                        url, domain, "INFO_DISCLOSURE",
                        "MEDIUM", "Firm", 5.3,
                        meta["cwe"], meta["owasp"],
                        evidence,
                        "Error details expose internal structure to attackers",
                        "Disable verbose errors in production",
                        statusCode, method
                    )
                break

    # ── OPEN REDIRECT ─────────────────────────────────

    def checkOpenRedirect(self, url, domain, statusCode,
                           resHeaders, method):
        if statusCode not in [301, 302, 303, 307, 308]:
            return

        headerDict = {}
        for h in resHeaders:
            if ":" in h:
                k, v = h.split(":", 1)
                headerDict[k.lower().strip()] = v.strip()

        location  = headerDict.get("location", "")
        urlLower  = url.lower()
        params    = ["redirect=", "url=", "next=",
                     "return=", "goto=", "dest="]

        for param in params:
            if param in urlLower:
                if (location.startswith("http") and
                        domain not in location):
                    evidence = ("Open redirect to external URL: " +
                                location[:60])
                    meta = VULN_META["OPEN_REDIRECT"]
                    if not self.isDuplicate(domain,
                                            "OPEN_REDIRECT", evidence):
                        self.addFinding(
                            url, domain, "OPEN_REDIRECT",
                            meta["severity"], meta["confidence"],
                            meta["cvss"], meta["cwe"], meta["owasp"],
                            evidence,
                            "Users redirected to phishing/malicious sites",
                            "Whitelist allowed redirect destinations",
                            statusCode, method
                        )
                break

    # ── EXPOSED FILES ─────────────────────────────────

    def checkExposedFiles(self, url, domain, statusCode, method):
        if statusCode != 200:
            return

        sensitiveFiles = [
            ("/.git/config",   "Git config file exposed"),
            ("/.env",          ".env file exposed - credentials at risk"),
            ("/config.php",    "PHP config file exposed"),
            ("/wp-config.php", "WordPress config file exposed"),
            ("/.htaccess",     ".htaccess file exposed"),
            ("/backup.sql",    "SQL backup file exposed"),
            ("/database.sql",  "Database dump exposed"),
            ("/config.json",   "JSON config file exposed"),
            ("/phpinfo.php",   "phpinfo() page exposed"),
            ("/.DS_Store",     ".DS_Store file exposed - directory structure leaked"),
        ]

        urlLower = url.lower().split("?")[0]
        meta     = VULN_META["EXPOSED_FILE"]

        for (path, evidence) in sensitiveFiles:
            if urlLower.endswith(path.lower()):
                if not self.isDuplicate(domain,
                                        "EXPOSED_FILE", evidence):
                    self.addFinding(
                        url, domain, "EXPOSED_FILE",
                        meta["severity"], meta["confidence"],
                        meta["cvss"], meta["cwe"], meta["owasp"],
                        evidence,
                        "Sensitive configuration or data file accessible publicly",
                        "Remove file from web root or restrict access via server config",
                        statusCode, method
                    )
                break

    # ── RATE LIMITING ─────────────────────────────────

    def checkRateLimit(self, url, domain, resHeaders,
                       statusCode, method):
        headerDict = {}
        for h in resHeaders:
            if ":" in h:
                k, v = h.split(":", 1)
                headerDict[k.lower().strip()] = v.strip()

        hasRateLimit = any(
            h in headerDict
            for h in ["x-ratelimit-limit", "ratelimit-limit",
                       "x-rate-limit", "retry-after"]
        )

        urlLower = url.lower()
        isLoginEndpoint = any(
            p in urlLower
            for p in ["/login", "/signin", "/auth",
                       "/token", "/password"]
        )

        if isLoginEndpoint and not hasRateLimit:
            evidence = "No rate limiting headers on authentication endpoint"
            meta = VULN_META["RATE_LIMIT"]
            if not self.isDuplicate(domain, "RATE_LIMIT", evidence):
                self.addFinding(
                    url, domain, "RATE_LIMIT",
                    meta["severity"], meta["confidence"],
                    meta["cvss"], meta["cwe"], meta["owasp"],
                    evidence,
                    "Endpoint vulnerable to brute-force and credential stuffing attacks",
                    "Implement rate limiting (e.g., 5 attempts per minute per IP)",
                    statusCode, method
                )

    # ── ADD FINDING ───────────────────────────────────

    def addFinding(self, url, domain, vulnType, severity,
                   confidence, cvss, cwe, owasp,
                   evidence, impact, fix, statusCode, method):
        self._count += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        finding = {
            "id":           self._count,
            "url":          url,
            "domain":       domain,
            "type":         vulnType,
            "severity":     severity,
            "confidence":   confidence,
            "cvss":         cvss,
            "cwe":          cwe,
            "owasp":        owasp,
            "evidence":     evidence,
            "impact":       impact,
            "fix":          fix,
            "status_code":  statusCode,
            "method":       method,
            "timestamp":    timestamp,
            # For Flask API compatibility
            "vulnerability_type": vulnType,
            "parameter":    evidence,
            "cvss_score":   cvss,
        }

        self._findings.append(finding)
        self._domain_findings[domain].append(finding)

        shortUrl = (url[:45] + "..." if len(url) > 45 else url)

        self._tableModel.addRow([
            "[" + severity + "]",
            "[" + confidence + "]",
            vulnType,
            evidence[:55],
            domain,
            cwe,
            str(cvss),
        ])

        self.updateStats()
        self.sendToAPI(finding)

        print(
            "[" + severity + "][" + confidence + "] " + vulnType +
            " | " + domain +
            " | Evidence: " + evidence[:50] +
            " | " + cwe +
            " | " + owasp
        )

    def sendToAPI(self, finding):
        try:
            data = json.dumps(finding)
            req  = urllib2.Request(
                "http://localhost:5000/api/burp/finding",
                data,
                {"Content-Type": "application/json"}
            )
            urllib2.urlopen(req, timeout=2)
        except Exception as e:
            print("[VulnScanner Pro] API error: " + str(e))

    # ── STATS ─────────────────────────────────────────

    def updateStats(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        total_cvss = 0.0
        for f in self._findings:
            s = f.get("severity", "LOW")
            if s in counts:
                counts[s] += 1
            total_cvss += float(f.get("cvss", 0))

        risk = 0.0
        if self._findings:
            risk = round(total_cvss / len(self._findings), 1)

        self._statsLabel.setText(
            "  Total: " + str(len(self._findings)) +
            "  |  CRITICAL: " + str(counts["CRITICAL"]) +
            "  HIGH: " + str(counts["HIGH"]) +
            "  MEDIUM: " + str(counts["MEDIUM"]) +
            "  LOW: " + str(counts["LOW"]) +
            "  |  Avg CVSS: " + str(risk) +
            "  |  Domains: " + str(len(self._domain_findings))
        )

    def clearResults(self):
        self._tableModel.setRowCount(0)
        self._findings        = []
        self._seen_hashes     = set()
        self._domain_findings = defaultdict(list)
        self._request_counts  = defaultdict(int)
        self._count           = 0
        self._statsLabel.setText(
            "  Total: 0  |  CRITICAL: 0  HIGH: 0  MEDIUM: 0  LOW: 0"
            "  |  Avg CVSS: 0.0  |  Domains: 0"
        )
        print("[VulnScanner Pro] Results cleared")

    def exportJSON(self):
        try:
            counts = {"CRITICAL": 0, "HIGH": 0,
                      "MEDIUM": 0, "LOW": 0}
            total_cvss = 0.0
            for f in self._findings:
                s = f.get("severity", "LOW")
                if s in counts:
                    counts[s] += 1
                total_cvss += float(f.get("cvss", 0))

            risk_score = 0.0
            if self._findings:
                risk_score = round(
                    total_cvss / len(self._findings), 1
                )

            report = {
                "report_metadata": {
                    "generated_at": datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "scanner": "VulnScanner Pro",
                    "total_domains": len(self._domain_findings),
                },
                "scan_summary": {
                    "total_findings": len(self._findings),
                    "critical":       counts["CRITICAL"],
                    "high":           counts["HIGH"],
                    "medium":         counts["MEDIUM"],
                    "low":            counts["LOW"],
                    "average_cvss":   risk_score,
                    "overall_risk": (
                        "CRITICAL" if counts["CRITICAL"] > 0 else
                        "HIGH"     if counts["HIGH"] > 0 else
                        "MEDIUM"   if counts["MEDIUM"] > 0 else
                        "LOW"
                    ),
                },
                "findings_by_domain": {
                    d: v for d, v in self._domain_findings.items()
                },
                "all_findings": self._findings,
            }

            with open("vulnscanner_report.json", "w") as f:
                json.dump(report, f, indent=2)

            print("[VulnScanner Pro] Report saved: "
                  "vulnscanner_report.json")
            print("[VulnScanner Pro] Summary: " +
                  str(len(self._findings)) + " findings across " +
                  str(len(self._domain_findings)) + " domains")

        except Exception as e:
            print("[VulnScanner Pro] Export error: " + str(e))

    # ── UI ────────────────────────────────────────────

    def buildUI(self):
        panel = JPanel(BorderLayout())
        panel.setBackground(Color(18, 18, 18))

        # Header
        headerPanel = JPanel()
        headerPanel.setBackground(Color(10, 10, 10))
        headerLabel = JLabel(
            "  VulnScanner Pro  |  "
            "Context-Aware  |  "
            "CWE/OWASP Mapped  |  "
            "Deduplicated"
        )
        headerLabel.setForeground(Color(0, 220, 120))
        headerLabel.setFont(Font("Consolas", Font.BOLD, 14))
        headerPanel.add(headerLabel)

        # Table
        table = JTable(self._tableModel)
        table.setBackground(Color(28, 28, 28))
        table.setForeground(Color(220, 220, 220))
        table.setGridColor(Color(45, 45, 45))
        table.setFont(Font("Consolas", Font.PLAIN, 12))
        table.setRowHeight(22)
        table.getTableHeader().setBackground(Color(10, 10, 10))
        table.getTableHeader().setForeground(Color(0, 220, 120))
        table.getTableHeader().setFont(
            Font("Consolas", Font.BOLD, 12)
        )

        col = table.getColumnModel()
        col.getColumn(0).setPreferredWidth(90)
        col.getColumn(1).setPreferredWidth(90)
        col.getColumn(2).setPreferredWidth(160)
        col.getColumn(3).setPreferredWidth(320)
        col.getColumn(4).setPreferredWidth(160)
        col.getColumn(5).setPreferredWidth(80)
        col.getColumn(6).setPreferredWidth(50)

        tableScroll = JScrollPane(table)

        # Bottom panel
        bottomPanel = JPanel(BorderLayout())
        bottomPanel.setBackground(Color(10, 10, 10))

        btnPanel = JPanel()
        btnPanel.setBackground(Color(10, 10, 10))

        clearBtn = JButton("Clear")
        clearBtn.addActionListener(lambda e: self.clearResults())
        clearBtn.setBackground(Color(160, 40, 40))
        clearBtn.setForeground(Color.WHITE)
        clearBtn.setFont(Font("Consolas", Font.BOLD, 11))

        dashBtn = JButton("Dashboard")
        dashBtn.addActionListener(lambda e: self.openDashboard())
        dashBtn.setBackground(Color(30, 90, 180))
        dashBtn.setForeground(Color.WHITE)
        dashBtn.setFont(Font("Consolas", Font.BOLD, 11))

        exportBtn = JButton("Export JSON")
        exportBtn.addActionListener(lambda e: self.exportJSON())
        exportBtn.setBackground(Color(20, 130, 70))
        exportBtn.setForeground(Color.WHITE)
        exportBtn.setFont(Font("Consolas", Font.BOLD, 11))

        btnPanel.add(clearBtn)
        btnPanel.add(dashBtn)
        btnPanel.add(exportBtn)

        statsLabel = JLabel(
            "  Total: 0  |  CRITICAL: 0  "
            "HIGH: 0  MEDIUM: 0  LOW: 0  "
            "|  Avg CVSS: 0.0  |  Domains: 0"
        )
        statsLabel.setForeground(Color(160, 160, 160))
        statsLabel.setFont(Font("Consolas", Font.PLAIN, 11))
        self._statsLabel = statsLabel

        bottomPanel.add(btnPanel,    BorderLayout.WEST)
        bottomPanel.add(statsLabel,  BorderLayout.CENTER)

        panel.add(headerPanel,  BorderLayout.NORTH)
        panel.add(tableScroll,  BorderLayout.CENTER)
        panel.add(bottomPanel,  BorderLayout.SOUTH)

        return panel

    def openDashboard(self):
        try:
            import java.awt.Desktop as Desktop
            import java.net.URI as URI
            Desktop.getDesktop().browse(
                URI("http://localhost:5173")
            )
        except Exception as e:
            print("[VulnScanner Pro] Open: http://localhost:5173")