USE vuln_scanner_db;

-- Insert default admin user
-- Password: admin@123 (hashed)
INSERT INTO users (username, email, password_hash, role)
VALUES (
    'admin',
    'admin@vulnscanner.com',
    '$2b$12$placeholder_hash_here',
    'admin'
);

-- Insert sample tester user
INSERT INTO users (username, email, password_hash, role)
VALUES (
    'tester1',
    'tester@vulnscanner.com',
    '$2b$12$placeholder_hash_here',
    'tester'
);
