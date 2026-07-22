-- WebAuthn passkey credentials
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    credential_id BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    attestation_type VARCHAR(64) DEFAULT '',
    transports TEXT DEFAULT '[]',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_credentials_cred_id ON webauthn_credentials(credential_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id ON webauthn_credentials(user_id);
