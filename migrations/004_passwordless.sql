-- Magic link passwordless tokens (prefix: magic_)
-- Reset tokens stay in password_reset_tokens (prefix: prt_)
CREATE TABLE IF NOT EXISTS passwordless_tokens (
    token TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    state TEXT,
    response_type TEXT DEFAULT 'code',
    scope TEXT DEFAULT 'openid',
    audience TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_passwordless_tokens_expires ON passwordless_tokens(expires_at);

-- Add email/passwordless connection
INSERT INTO connections (id, name, strategy)
VALUES ('con_email', 'email', 'email')
ON CONFLICT (id) DO NOTHING;
