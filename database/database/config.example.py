# Copy this file to config.py and fill in your details
# NEVER push config.py to GitHub (it's in .gitignore)

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "YOUR_MYSQL_PASSWORD",
    "database": "vuln_scanner_db",
    "port": 3306
}

JWT_SECRET_KEY = "YOUR_SECRET_KEY_HERE"
JWT_EXPIRY_HOURS = 24

FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000

WEBSOCKET_PORT = 5001
