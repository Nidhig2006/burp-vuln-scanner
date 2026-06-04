# 🔍 BurpVulnScanner

A powerful **real-time web vulnerability scanner** built as a Burp Suite Extension with a React + Vite dashboard.

![Status](https://img.shields.io/badge/Status-Active-green)
![Python](https://img.shields.io/badge/Python-3.13-blue)
![React](https://img.shields.io/badge/React-Vite-purple)
![MySQL](https://img.shields.io/badge/Database-MySQL-orange)
![Burp](https://img.shields.io/badge/Burp%20Suite-Extension-red)

---

## 🚀 Features

- 🔴 SQL Injection Detection
- 🟠 XSS Cross-Site Scripting Detection
- 🟡 Security Headers Checker
- 🟢 Sensitive Data Scanner (API keys, JWT, AWS credentials)
- 🔵 Open Redirect Detector
- ⚪ Information Disclosure Checker
- ⚡ WebSocket Real-time Updates
- 📊 CVSS Severity Scoring
- 📄 PDF Report Export
- 🔐 JWT Authentication
- 🗄️ MySQL Persistent Storage

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Burp Extension | Python 2.7 (Jython) |
| Backend API | Python 3 + Flask + Flask-SocketIO |
| Database | MySQL |
| Frontend | React + Vite + Tailwind CSS |
| Charts | Recharts |
| Authentication | JWT (Flask-JWT-Extended) |
| Real-time | WebSocket |
| PDF Export | jsPDF + html2canvas |

---
## 📁 Project Structure

```
burp-vuln-scanner/
├── burp-extension/
│   └── extension.py          # Jython Burp Suite extension
├── backend/
│   ├── app.py                # Flask REST API + WebSocket server
│   ├── db.py                 # MySQL connection manager
│   ├── models.py             # Database queries and models
│   ├── requirements.txt      # Python dependencies
│   └── scanner/
│       ├── sqli.py           # SQL Injection detector
│       ├── xss.py            # XSS detector
│       ├── headers.py        # Security headers checker
│       ├── sensitive.py      # Sensitive data scanner
│       ├── redirect.py       # Open redirect detector
│       └── info_disclosure.py
├── frontend/
│   └── src/
│       ├── pages/
│       ├── components/
│       ├── context/
│       └── utils/
└── database/
    ├── schema.sql
    └── seed.sql
```

## ⚙️ Setup Instructions

### Prerequisites
- Python 3.x
- Node.js 18+
- MySQL 8.x
- Burp Suite Community Edition
- Jython 2.7 standalone JAR

---

### 1. Clone the Repository
```bash
git clone https://github.com/Nidhig2006/burp-vuln-scanner.git
cd burp-vuln-scanner
```

---

### 2. Setup MySQL Database
```sql
CREATE DATABASE vuln_scanner_db;
USE vuln_scanner_db;
```
Then create tables from `database/schema.sql`

---

### 3. Setup Backend
```bash
cd backend
pip install -r requirements.txt
```

Create `.env` file in backend folder:
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=vuln_scanner_db
DB_PORT=3306
JWT_SECRET=your_jwt_secret_key
FLASK_PORT=5000
WEBSOCKET_PORT=5001

Run the server:
```bash
python app.py
```
Backend runs on `http://localhost:5000`

---

### 4. Setup Frontend
```bash
cd frontend
npm install
npm run dev
```
Frontend runs on `http://localhost:5173`

---

### 5. Setup Burp Suite Extension
1. Download **Jython Standalone JAR** from https://www.jython.org/download
2. Open **Burp Suite Community Edition**
3. Go to **Extensions** → **Extensions Settings**
4. Under **Python Environment** → select the Jython JAR file
5. Go to **Extensions** → **Installed** → **Add**
6. Set Extension type to **Python**
7. Select `burp-extension/extension.py`
8. Click **Next** — you should see **VulnScanner** tab appear

---

### 6. Start Scanning
1. Make sure Flask backend is running
2. Make sure React frontend is running
3. Configure browser proxy to `127.0.0.1:8080`
4. Browse any target website through Burp
5. Watch findings appear live in:
   - **VulnScanner tab** inside Burp Suite
   - **React Dashboard** at `localhost:5173`

---

## 🔍 Vulnerability Detection

| Type | Severity | CVSS |
|---|---|---|
| SQL Injection | CRITICAL | 9.8 |
| Sensitive Data (AWS/JWT keys) | CRITICAL | 9.8 |
| XSS | HIGH | 7.4 |
| Missing HSTS | HIGH | 7.4 |
| Missing CSP | HIGH | 6.1 |
| Open Redirect | MEDIUM | 6.1 |
| Missing X-Frame-Options | MEDIUM | 4.3 |
| Server Version Disclosure | LOW | 3.1 |

---

## 🌿 Branch Structure

| Branch | Purpose |
|---|---|
| `main` | Stable production code |
| `dev` | Development integration |
| `feature/database` | MySQL schema |
| `feature/backend` | Flask API + scanner modules |
| `feature/burp-extension` | Jython Burp extension |
| `feature/frontend` | React Vite dashboard |

---

## 👩‍💻 Author

**Nidhi G** — [@Nidhig2006](https://github.com/Nidhig2006)

---

## ⭐ Star this project if you found it useful!
