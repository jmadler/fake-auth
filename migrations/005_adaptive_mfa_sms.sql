-- user_known_ips: track known IPs per user for adaptive MFA
CREATE TABLE IF NOT EXISTS user_known_ips (
    user_id VARCHAR(255) NOT NULL,
    ip VARCHAR(64) NOT NULL,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, ip),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_user_known_ips_user_id ON user_known_ips(user_id);

-- users.phone_number for SMS passwordless lookup
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_number VARCHAR(32);
CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone_number);

-- Extend passwordless_tokens for SMS OTP: add token_type, phone, code
ALTER TABLE passwordless_tokens ADD COLUMN IF NOT EXISTS token_type VARCHAR(32) DEFAULT 'magiclink';
ALTER TABLE passwordless_tokens ADD COLUMN IF NOT EXISTS phone VARCHAR(32);
ALTER TABLE passwordless_tokens ADD COLUMN IF NOT EXISTS code VARCHAR(16);
