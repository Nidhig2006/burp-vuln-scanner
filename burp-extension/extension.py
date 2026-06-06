# -*- coding: utf-8 -*-
# Burp Suite Extension - VulnScanner
# Language: Jython (Python 2.7)

from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import JPanel, JScrollPane, JTable, JButton, JLabel
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, Color, Font
import json
import re
import urllib2

class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("VulnScanner")

        self._tableModel = DefaultTableModel(
            ["#", "URL", "Type", "Severity", "Parameter", "CVSS"], 0
        )
        self._findings = []
        self._count = 0

        self._panel = self.buildUI()

        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)

        print("[VulnScanner] Extension loaded successfully!")
        print("[VulnScanner] Dashboard: http://localhost:5000")

    def getTabCaption(self):
        return "VulnScanner"

    def getUiComponent(self):
        return self._panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        try:
            analyzedRequest = self._helpers.analyzeRequest(messageInfo)
            analyzedResponse = self._helpers.analyzeResponse(
                messageInfo.getResponse()
            )
            url = str(analyzedRequest.getUrl())
            responseBody = self._helpers.bytesToString(
                messageInfo.getResponse()
            )
            responseHeaders = analyzedResponse.getHeaders()
            statusCode = analyzedResponse.getStatusCode()

            self.checkSecurityHeaders(url, responseHeaders)
            self.checkSensitiveData(url, responseBody)
            self.checkInfoDisclosure(url, responseBody, responseHeaders)
            self.checkSQLErrors(url, responseBody)
            self.checkXSSReflection(url, responseBody)
            self.checkOpenRedirect(url, statusCode, responseHeaders)

        except Exception as e:
            print("[VulnScanner] Error: " + str(e))

    def checkSecurityHeaders(self, url, responseHeaders):
        headerNames = [h.split(":")[0].lower() for h in responseHeaders]
        securityHeaders = {
            "strict-transport-security": ("SECURITY_HEADERS", "HIGH", 7.4),
            "content-security-policy":   ("SECURITY_HEADERS", "HIGH", 6.1),
            "x-frame-options":           ("SECURITY_HEADERS", "MEDIUM", 4.3),
            "x-content-type-options":    ("SECURITY_HEADERS", "MEDIUM", 4.3),
            "referrer-policy":           ("SECURITY_HEADERS", "LOW", 3.1),
        }
        for header, (vtype, severity, cvss) in securityHeaders.items():
            if header not in headerNames:
                self.addFinding(url, vtype, severity,
                                "Missing: " + header, cvss)

    def checkSensitiveData(self, url, responseBody):
        patterns = {
            "AWS_KEY":      r"AKIA[0-9A-Z]{16}",
            "JWT_TOKEN":    r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
            "PRIVATE_KEY":  r"-----BEGIN (RSA )?PRIVATE KEY-----",
            "GOOGLE_KEY":   r"AIza[0-9A-Za-z\-_]{35}",
            "PASSWORD_URL": r"[?&]password=[^&]+",
        }
        for name, pattern in patterns.items():
            if re.search(pattern, responseBody):
                self.addFinding(url, "SENSITIVE_DATA", "CRITICAL",
                                "Found: " + name, 9.8)

    def checkInfoDisclosure(self, url, responseBody, responseHeaders):
        headerDict = {}
        for h in responseHeaders:
            if ":" in h:
                k, v = h.split(":", 1)
                headerDict[k.lower().strip()] = v.strip()

        serverHeaders = ["server", "x-powered-by", "x-aspnet-version"]
        for h in serverHeaders:
            if h in headerDict:
                self.addFinding(url, "INFO_DISCLOSURE", "LOW",
                                h + ": " + headerDict[h], 3.1)

        errorPatterns = [
            "stack trace", "at java.", "traceback",
            "mysql_fetch", "ORA-", "syntax error"
        ]
        for pattern in errorPatterns:
            if pattern.lower() in responseBody.lower():
                self.addFinding(url, "INFO_DISCLOSURE", "MEDIUM",
                                "Error message: " + pattern, 5.3)
                break

    def checkSQLErrors(self, url, responseBody):
        sqlErrors = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
            "ora-01756",
            "microsoft ole db provider for sql server",
        ]
        for error in sqlErrors:
            if error.lower() in responseBody.lower():
                self.addFinding(url, "SQL_INJECTION", "CRITICAL",
                                "SQL error in response", 9.8)
                break

    def checkXSSReflection(self, url, responseBody):
        xssPayloads = [
            "<script>", "javascript:", "onerror=",
            "onload=", "alert(", "<svg"
        ]
        urlLower = url.lower()
        for payload in xssPayloads:
            if payload in urlLower and payload in responseBody.lower():
                self.addFinding(url, "XSS", "HIGH",
                                "Reflected payload: " + payload, 7.4)
                break

    def checkOpenRedirect(self, url, statusCode, responseHeaders):
        if statusCode in [301, 302, 303, 307, 308]:
            headerDict = {}
            for h in responseHeaders:
                if ":" in h:
                    k, v = h.split(":", 1)
                    headerDict[k.lower().strip()] = v.strip()
            location = headerDict.get("location", "")
            redirectParams = ["redirect=", "url=", "next=", "return="]
            for param in redirectParams:
                if param in url.lower() and location.startswith("http"):
                    self.addFinding(url, "OPEN_REDIRECT", "MEDIUM",
                                    "Redirects to: " + location, 6.1)
                    break

    def addFinding(self, url, vulnType, severity, parameter, cvss):
        self._count += 1
        finding = {
            "url": url,
            "vulnerability_type": vulnType,
            "severity": severity,
            "parameter": parameter,
            "cvss_score": cvss
        }
        self._findings.append(finding)
        self._tableModel.addRow([
            self._count,
            url[:60] + "..." if len(url) > 60 else url,
            vulnType, severity, parameter, str(cvss)
        ])
        self.sendToAPI(finding)
        print("[VulnScanner] Found: " + vulnType + " at " + url)

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
            print("[VulnScanner] API error: " + str(e))

    def buildUI(self):
        panel = JPanel(BorderLayout())
        panel.setBackground(Color(30, 30, 30))

        headerPanel = JPanel()
        headerPanel.setBackground(Color(20, 20, 20))
        headerLabel = JLabel("  VulnScanner - Real-time Vulnerability Detector")
        headerLabel.setForeground(Color.WHITE)
        headerLabel.setFont(Font("Arial", Font.BOLD, 16))
        headerPanel.add(headerLabel)

        table = JTable(self._tableModel)
        table.setBackground(Color(40, 40, 40))
        table.setForeground(Color.WHITE)
        table.setGridColor(Color(60, 60, 60))
        table.getTableHeader().setBackground(Color(20, 20, 20))
        table.getTableHeader().setForeground(Color.WHITE)
        table.setRowHeight(25)
        tableScroll = JScrollPane(table)

        btnPanel = JPanel()
        btnPanel.setBackground(Color(20, 20, 20))

        clearBtn = JButton("Clear Results")
        clearBtn.addActionListener(lambda e: self.clearResults())
        clearBtn.setBackground(Color(180, 50, 50))
        clearBtn.setForeground(Color.WHITE)

        dashboardBtn = JButton("Open Dashboard")
        dashboardBtn.addActionListener(lambda e: self.openDashboard())
        dashboardBtn.setBackground(Color(50, 100, 180))
        dashboardBtn.setForeground(Color.WHITE)

        btnPanel.add(clearBtn)
        btnPanel.add(dashboardBtn)

        panel.add(headerPanel, BorderLayout.NORTH)
        panel.add(tableScroll, BorderLayout.CENTER)
        panel.add(btnPanel, BorderLayout.SOUTH)

        return panel

    def clearResults(self):
        self._tableModel.setRowCount(0)
        self._findings = []
        self._count = 0
        print("[VulnScanner] Results cleared")

    def openDashboard(self):
        try:
            import java.awt.Desktop as Desktop
            import java.net.URI as URI
            Desktop.getDesktop().browse(URI("http://localhost:5173"))
        except Exception as e:
            print("[VulnScanner] Open browser: http://localhost:5173")