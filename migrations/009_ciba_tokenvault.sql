-- CIBA (Client Initiated Backchannel Authentication) requests
CREATE TABLE IF NOT EXISTS ciba_requests (
    auth_req_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    login_hint TEXT NOT NULL,
    scope TEXT DEFAULT 'openid',
    audience TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    user_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ciba_requests_status ON ciba_requests(status);
CREATE INDEX IF NOT EXISTS idx_ciba_requests_expires ON ciba_requests(expires_at);

-- Token Vault: store tokens by name for AI agents
CREATE TABLE IF NOT EXISTS token_vault (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    user_id TEXT NOT NULL,
    access_token_encrypted TEXT NOT NULL,
    metadata TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(name, user_id)
);
CREATE INDEX IF NOT EXISTS idx_token_vault_name_user ON token_vault(name, user_id);
CREATE INDEX IF NOT EXISTS idx_token_vault_user ON token_vault(user_id);
