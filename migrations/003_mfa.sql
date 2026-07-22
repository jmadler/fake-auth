-- MFA enrollment: TOTP secret and backup code hashes per user

CREATE TABLE IF NOT EXISTS mfa_enrollment (
    user_id TEXT PRIMARY KEY,
    totp_secret TEXT NOT NULL,
    backup_codes_hash TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
