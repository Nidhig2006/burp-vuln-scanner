# -*- coding: utf-8 -*-
# Burp Suite Extension - VulnScanner Pro
# Language: Jython (Python 2.7)

from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import JPanel, JScrollPane, JTable, JButton, JLabel, JTextArea
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, Color, Font, Dimension
import json
import re
import urllib2
import hashlib
from datetime import datetime

class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("VulnScanner Pro")

        self._tableModel = DefaultTableModel(
            ["Severity", "Confidence", "Type", "Evidence", "URL", "CVSS"], 0
        )
        self._findings = []
        self._seen_hashes = set()
        self._count = 0

        self._panel = self.buildUI()
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)

        print("[VulnScanner Pro] Extension loaded successfully!")
        print("[VulnScanner Pro] Dashboard: http://localhost:5173")

    def getTabCaption(self):
        return "VulnScanner Pro"

    def getUiComponent(self):
        return self._panel

    # ── DEDUPLICATION ─────────────────────────────────

    def isDuplicate(self, url, vulnType, evidence):
        base_url = url.split("?")[0].split("#")[0]
        key = base_url + "|" + vulnType + "|" + evidence[:30]
        h = hashlib.md5(key.encode('utf-8')).hexdigest()
        if h in self._seen_hashes:
            return True
        self._seen_hashes.add(h)
        return False

    # ── HTTP LISTENER ─────────────────────────────────

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        try:
            analyzedRequest  = self._helpers.analyzeRequest(messageInfo)
            analyzedResponse = self._helpers.analyzeResponse(
                messageInfo.getResponse()
            )
            url          = str(analyzedRequest.getUrl())
            method       = analyzedRequest.getMethod()
            responseBody = self._helpers.bytesToString(
                messageInfo.getResponse()
            )
            reqHeaders   = analyzedRequest.getHeaders()
            resHeaders   = analyzedResponse.getHeaders()
            statusCode   = analyzedResponse.getStatusCode()

            self.checkSecurityHeaders(url, resHeaders, statusCode, method)
            self.checkSensitiveData(url, responseBody, statusCode, method)
            self.checkInfoDisclosure(url, responseBody, resHeaders,
                                     statusCode, method)
            self.checkSQLErrors(url, responseBody, statusCode, method)
            self.checkXSSReflection(url, responseBody, statusCode, method)
            self.checkOpenRedirect(url, statusCode, resHeaders, method)

        except Exception as e:
            print("[VulnScanner Pro] Error: " + str(e))

    # ── DETECTORS ─────────────────────────────────────

    def checkSecurityHeaders(self, url, resHeaders, statusCode, method):
        headerNames = [h.split(":")[0].lower() for h in resHeaders]

        checks = [
            (
                "strict-transport-security",
                "HIGH", "Certain", 7.4,
                "Strict-Transport-Security header absent",
                "Site can be downgraded from HTTPS to HTTP enabling MITM attacks",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            ),
            (
                "content-security-policy",
                "HIGH", "Certain", 6.1,
                "Content-Security-Policy header absent",
                "No protection against XSS and data injection attacks",
                "Add a strict CSP policy restricting script sources"
            ),
            (
                "x-frame-options",
                "MEDIUM", "Certain", 4.3,
                "X-Frame-Options header absent",
                "Page can be embedded in iframes enabling Clickjacking attacks",
                "Add: X-Frame-Options: DENY"
            ),
            (
                "x-content-type-options",
                "MEDIUM", "Certain", 4.3,
                "X-Content-Type-Options header absent",
                "Browser may MIME-sniff responses causing XSS",
                "Add: X-Content-Type-Options: nosniff"
            ),
            (
                "referrer-policy",
                "LOW", "Certain", 3.1,
                "Referrer-Policy header absent",
                "Sensitive URLs may leak to third party sites via Referer header",
                "Add: Referrer-Policy: strict-origin-when-cross-origin"
            ),
            (
                "permissions-policy",
                "LOW", "Certain", 3.1,
                "Permissions-Policy header absent",
                "Browser features like camera/microphone/location not restricted",
                "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"
            ),
        ]

        for (header, severity, confidence, cvss,
             evidence, impact, fix) in checks:
            if header not in headerNames:
                if not self.isDuplicate(url, "SECURITY_HEADERS", evidence):
                    self.addFinding(
                        url, "SECURITY_HEADERS",
                        severity, confidence, cvss,
                        evidence, impact, fix,
                        statusCode, method
                    )

    def checkInfoDisclosure(self, url, responseBody,
                             resHeaders, statusCode, method):
        headerDict = {}
        for h in resHeaders:
            if ":" in h:
                k, v = h.split(":", 1)
                headerDict[k.lower().strip()] = v.strip()

        serverHeaders = {
            "server":            "Server header reveals web server software",
            "x-powered-by":      "X-Powered-By reveals backend technology",
            "x-aspnet-version":  "X-AspNet-Version reveals .NET framework version",
            "x-generator":       "X-Generator reveals CMS or framework",
        }

        for h, desc in serverHeaders.items():
            if h in headerDict:
                evidence = desc + " [" + headerDict[h] + "]"
                if not self.isDuplicate(url, "INFO_DISCLOSURE", evidence):
                    self.addFinding(
                        url, "INFO_DISCLOSURE",
                        "LOW", "Certain", 3.1,
                        evidence,
                        "Attacker can fingerprint server and target version-specific exploits",
                        "Remove or obfuscate the " + h + " header",
                        statusCode, method
                    )

        errorPatterns = {
            "stack trace":  "Stack trace exposed in response body",
            "at java.":     "Java exception stack trace exposed",
            "traceback":    "Python traceback exposed in response",
            "mysql_fetch":  "MySQL function name exposed in error",
            "ORA-":         "Oracle database error exposed",
            "syntax error": "Syntax error message exposed",
            "fatal error":  "PHP fatal error exposed",
        }

        for pattern, evidence in errorPatterns.items():
            if pattern.lower() in responseBody.lower():
                if not self.isDuplicate(url, "INFO_DISCLOSURE", evidence):
                    self.addFinding(
                        url, "INFO_DISCLOSURE",
                        "MEDIUM", "Firm", 5.3,
                        evidence,
                        "Error details help attacker understand internal structure",
                        "Disable detailed error messages in production",
                        statusCode, method
                    )
                break

    def checkSensitiveData(self, url, responseBody, statusCode, method):
        patterns = [
            (
                r"AKIA[0-9A-Z]{16}",
                "CRITICAL", "Certain", 9.8,
                "AWS Access Key ID exposed in response",
                "Full AWS account compromise possible",
                "Rotate key immediately and remove from codebase"
            ),
            (
                r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
                "HIGH", "Firm", 7.5,
                "JWT Token exposed in response body",
                "Authentication token can be stolen and reused",
                "Never expose JWT tokens in response bodies"
            ),
            (
                r"-----BEGIN (RSA )?PRIVATE KEY-----",
                "CRITICAL", "Certain", 9.8,
                "Private key exposed in response",
                "SSL/SSH private key compromise",
                "Remove private key immediately and regenerate"
            ),
            (
                r"AIza[0-9A-Za-z\-_]{35}",
                "CRITICAL", "Certain", 9.8,
                "Google API Key exposed in response",
                "Unauthorized API usage and billing abuse possible",
                "Restrict key in Google Console and rotate"
            ),
            (
                r"[?&]password=[^&\s]{3,}",
                "HIGH", "Certain", 7.5,
                "Password transmitted in URL parameter",
                "Credentials visible in browser history, logs and referrer headers",
                "Use POST requests with body for credentials"
            ),
            (
                r"(192\.168\.|10\.\d+\.|172\.1[6-9]\.|172\.2[0-9]\.)\d+\.\d+",
                "LOW", "Firm", 3.1,
                "Internal IP address exposed in response",
                "Internal network topology revealed to attacker",
                "Remove internal IPs from public responses"
            ),
        ]

        for (pattern, severity, confidence, cvss,
             evidence, impact, fix) in patterns:
            match = re.search(pattern, responseBody)
            if match:
                matched_text = match.group(0)[:30]
                full_evidence = evidence + " [" + matched_text + "...]"
                if not self.isDuplicate(url, "SENSITIVE_DATA", evidence):
                    self.addFinding(
                        url, "SENSITIVE_DATA",
                        severity, confidence, cvss,
                        full_evidence, impact, fix,
                        statusCode, method
                    )

    def checkSQLErrors(self, url, responseBody, statusCode, method):
        sqlErrors = [
            (
                "you have an error in your sql syntax",
                "MySQL syntax error in response",
                "Certain"
            ),
            (
                "warning: mysql",
                "MySQL warning exposed in response",
                "Certain"
            ),
            (
                "unclosed quotation mark after the character string",
                "MSSQL unclosed quote error",
                "Certain"
            ),
            (
                "ora-01756",
                "Oracle SQL error in response",
                "Certain"
            ),
            (
                "microsoft ole db provider for sql server",
                "MSSQL OLE DB error in response",
                "Certain"
            ),
            (
                "pg_query(): query failed",
                "PostgreSQL error in response",
                "Certain"
            ),
        ]

        for (pattern, evidence, confidence) in sqlErrors:
            if pattern.lower() in responseBody.lower():
                if not self.isDuplicate(url, "SQL_INJECTION", evidence):
                    self.addFinding(
                        url, "SQL_INJECTION",
                        "CRITICAL", confidence, 9.8,
                        evidence,
                        "Database error reveals query structure - SQL Injection likely possible",
                        "Use prepared statements. Never expose DB errors in production",
                        statusCode, method
                    )
                break

    def checkXSSReflection(self, url, responseBody, statusCode, method):
        xssPayloads = [
            (
                "<script>",
                "Script tag reflected unescaped in response",
                "Firm"
            ),
            (
                "javascript:",
                "Javascript protocol reflected in response",
                "Tentative"
            ),
            (
                "onerror=",
                "onerror event handler reflected in response",
                "Firm"
            ),
            (
                "onload=",
                "onload event handler reflected in response",
                "Firm"
            ),
            (
                "<svg",
                "SVG tag reflected in response enabling script execution",
                "Tentative"
            ),
        ]

        urlLower = url.lower()
        for (payload, evidence, confidence) in xssPayloads:
            if payload in urlLower and payload in responseBody.lower():
                if not self.isDuplicate(url, "XSS", evidence):
                    self.addFinding(
                        url, "XSS",
                        "HIGH", confidence, 7.4,
                        evidence,
                        "Attacker can execute scripts in victim browser stealing cookies/sessions",
                        "HTML encode all user input. Implement Content-Security-Policy",
                        statusCode, method
                    )
                break

    def checkOpenRedirect(self, url, statusCode, resHeaders, method):
        if statusCode not in [301, 302, 303, 307, 308]:
            return

        headerDict = {}
        for h in resHeaders:
            if ":" in h:
                k, v = h.split(":", 1)
                headerDict[k.lower().strip()] = v.strip()

        location = headerDict.get("location", "")
        redirectParams = [
            "redirect=", "url=", "next=",
            "return=", "goto=", "dest="
        ]

        for param in redirectParams:
            if param in url.lower():
                if location.startswith("http") and "localhost" not in location:
                    evidence = "Redirect to external URL: " + location[:50]
                    if not self.isDuplicate(url, "OPEN_REDIRECT", evidence):
                        self.addFinding(
                            url, "OPEN_REDIRECT",
                            "MEDIUM", "Firm", 6.1,
                            evidence,
                            "Users can be redirected to phishing/malicious sites",
                            "Whitelist allowed redirect destinations",
                            statusCode, method
                        )
                break

    # ── ADD FINDING ───────────────────────────────────

    def addFinding(self, url, vulnType, severity, confidence,
                   cvss, evidence, impact, fix, statusCode, method):
        self._count += 1
        timestamp = datetime.now().strftime("%H:%M:%S")

        finding = {
            "url": url,
            "vulnerability_type": vulnType,
            "severity": severity,
            "confidence": confidence,
            "cvss_score": cvss,
            "evidence": evidence,
            "impact": impact,
            "fix": fix,
            "status_code": statusCode,
            "method": method,
            "timestamp": timestamp,
            "parameter": evidence
        }

        self._findings.append(finding)

        short_url = url[:50] + "..." if len(url) > 50 else url

        self._tableModel.addRow([
            "[" + severity + "]",
            "[" + confidence + "]",
            vulnType,
            evidence[:60],
            short_url,
            str(cvss)
        ])

        self.sendToAPI(finding)

        print(
            "[" + severity + "][" + confidence + "] " + vulnType +
            " | URL: " + short_url +
            " | Evidence: " + evidence[:50] +
            " | Impact: " + impact[:50] +
            " | Fix: " + fix[:50]
        )

    def sendToAPI(self, finding):
        try:
            data = json.dumps(finding)
            req = urllib2.Request(
                "http://localhost:5000/api/burp/finding",
                data,
                {"Content-Type": "application/json"}
            )
            urllib2.urlopen(req, timeout=2)
        except Exception as e:
            print("[VulnScanner Pro] API error: " + str(e))

    # ── UI ────────────────────────────────────────────

    def buildUI(self):
        panel = JPanel(BorderLayout())
        panel.setBackground(Color(20, 20, 20))

        headerPanel = JPanel()
        headerPanel.setBackground(Color(15, 15, 15))
        headerLabel = JLabel(
            "  VulnScanner Pro - Professional Vulnerability Detector"
        )
        headerLabel.setForeground(Color(0, 200, 100))
        headerLabel.setFont(Font("Consolas", Font.BOLD, 15))
        headerPanel.add(headerLabel)

        table = JTable(self._tableModel)
        table.setBackground(Color(30, 30, 30))
        table.setForeground(Color.WHITE)
        table.setGridColor(Color(50, 50, 50))
        table.getTableHeader().setBackground(Color(15, 15, 15))
        table.getTableHeader().setForeground(Color(0, 200, 100))
        table.setFont(Font("Consolas", Font.PLAIN, 12))
        table.setRowHeight(22)

        col = table.getColumnModel()
        col.getColumn(0).setPreferredWidth(80)
        col.getColumn(1).setPreferredWidth(80)
        col.getColumn(2).setPreferredWidth(130)
        col.getColumn(3).setPreferredWidth(300)
        col.getColumn(4).setPreferredWidth(250)
        col.getColumn(5).setPreferredWidth(50)

        tableScroll = JScrollPane(table)

        btnPanel = JPanel()
        btnPanel.setBackground(Color(15, 15, 15))

        clearBtn = JButton("Clear Results")
        clearBtn.addActionListener(lambda e: self.clearResults())
        clearBtn.setBackground(Color(180, 50, 50))
        clearBtn.setForeground(Color.WHITE)
        clearBtn.setFont(Font("Consolas", Font.BOLD, 12))

        dashboardBtn = JButton("Open Dashboard")
        dashboardBtn.addActionListener(lambda e: self.openDashboard())
        dashboardBtn.setBackground(Color(30, 100, 200))
        dashboardBtn.setForeground(Color.WHITE)
        dashboardBtn.setFont(Font("Consolas", Font.BOLD, 12))

        exportBtn = JButton("Export JSON")
        exportBtn.addActionListener(lambda e: self.exportJSON())
        exportBtn.setBackground(Color(30, 150, 80))
        exportBtn.setForeground(Color.WHITE)
        exportBtn.setFont(Font("Consolas", Font.BOLD, 12))

        statsLabel = JLabel(
            "  Findings: 0 | Critical: 0 | High: 0 | Medium: 0 | Low: 0"
        )
        statsLabel.setForeground(Color(180, 180, 180))
        statsLabel.setFont(Font("Consolas", Font.PLAIN, 11))
        self._statsLabel = statsLabel

        btnPanel.add(clearBtn)
        btnPanel.add(dashboardBtn)
        btnPanel.add(exportBtn)
        btnPanel.add(statsLabel)

        panel.add(headerPanel, BorderLayout.NORTH)
        panel.add(tableScroll, BorderLayout.CENTER)
        panel.add(btnPanel, BorderLayout.SOUTH)

        return panel

    def updateStats(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self._findings:
            s = f.get("severity", "LOW")
            if s in counts:
                counts[s] += 1
        self._statsLabel.setText(
            "  Findings: " + str(len(self._findings)) +
            " | Critical: " + str(counts["CRITICAL"]) +
            " | High: " + str(counts["HIGH"]) +
            " | Medium: " + str(counts["MEDIUM"]) +
            " | Low: " + str(counts["LOW"])
        )

    def clearResults(self):
        self._tableModel.setRowCount(0)
        self._findings = []
        self._seen_hashes = set()
        self._count = 0
        self._statsLabel.setText(
            "  Findings: 0 | Critical: 0 | High: 0 | Medium: 0 | Low: 0"
        )
        print("[VulnScanner Pro] Results cleared")

    def exportJSON(self):
        try:
            report = {
                "scan_summary": {
                    "total_findings": len(self._findings),
                    "critical": sum(
                        1 for f in self._findings
                        if f.get("severity") == "CRITICAL"
                    ),
                    "high": sum(
                        1 for f in self._findings
                        if f.get("severity") == "HIGH"
                    ),
                    "medium": sum(
                        1 for f in self._findings
                        if f.get("severity") == "MEDIUM"
                    ),
                    "low": sum(
                        1 for f in self._findings
                        if f.get("severity") == "LOW"
                    ),
                    "timestamp": datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                },
                "findings": self._findings
            }
            with open("vulnscanner_report.json", "w") as f:
                json.dump(report, f, indent=2)
            print("[VulnScanner Pro] Report saved: vulnscanner_report.json")
        except Exception as e:
            print("[VulnScanner Pro] Export error: " + str(e))

    def openDashboard(self):
        try:
            import java.awt.Desktop as Desktop
            import java.net.URI as URI
            Desktop.getDesktop().browse(URI("http://localhost:5173"))
        except Exception as e:
            print("[VulnScanner Pro] Open: http://localhost:5173")