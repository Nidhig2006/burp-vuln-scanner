-- Create Database
CREATE DATABASE IF NOT EXISTS vuln_scanner_db;
USE vuln_scanner_db;

-- Users Table (JWT Authentication)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(150) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'tester') DEFAULT 'tester',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL
);

-- Scans Table (Each scan session)
CREATE TABLE IF NOT EXISTS scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    target_url VARCHAR(500) NOT NULL,
    scan_name VARCHAR(200),
    status ENUM('running', 'completed', 'stopped') DEFAULT 'running',
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    total_findings INT DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Findings Table (Each vulnerability found)
CREATE TABLE IF NOT EXISTS findings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    url VARCHAR(500) NOT NULL,
    parameter VARCHAR(200),
    vulnerability_type ENUM(
        'SQL_INJECTION',
        'XSS',
        'OPEN_REDIRECT',
        'SENSITIVE_DATA',
        'SECURITY_HEADERS',
        'INFO_DISCLOSURE'
    ) NOT NULL,
    severity ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO') NOT NULL,
    cvss_score DECIMAL(3,1) DEFAULT 0.0,
    payload VARCHAR(500),
    evidence TEXT,
    recommendation TEXT,
    status ENUM('open', 'fixed', 'false_positive') DEFAULT 'open',
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- HTTP Requests Table (Raw request/response logs)
CREATE TABLE IF NOT EXISTS http_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    finding_id INT,
    method VARCHAR(10) NOT NULL,
    url VARCHAR(500) NOT NULL,
    request_headers TEXT,
    request_body TEXT,
    response_code INT,
    response_headers TEXT,
    response_body TEXT,
    logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE SET NULL
);

-- Reports Table (Exported reports)
CREATE TABLE IF NOT EXISTS reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    user_id INT NOT NULL,
    report_name VARCHAR(200),
    format ENUM('PDF', 'HTML', 'JSON') DEFAULT 'PDF',
    file_path VARCHAR(500),
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);