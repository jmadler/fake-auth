-- Organizations (Auth0 B2B multi-tenant)
CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    display_name TEXT,
    metadata TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS org_members (
    org_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    PRIMARY KEY (org_id, user_id),
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_org_members_user_id ON org_members(user_id);

CREATE TABLE IF NOT EXISTS org_connections (
    org_id TEXT NOT NULL,
    connection_id TEXT NOT NULL,
    PRIMARY KEY (org_id, connection_id),
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (connection_id) REFERENCES connections(id) ON DELETE CASCADE
);

-- Self-service SSO: enterprise OIDC connections per org
CREATE TABLE IF NOT EXISTS enterprise_connections (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    name TEXT NOT NULL,
    domain_hint TEXT,
    issuer_url TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_enterprise_connections_org_id ON enterprise_connections(org_id);
CREATE INDEX IF NOT EXISTS idx_enterprise_connections_domain ON enterprise_connections(domain_hint);

-- Invitations
CREATE TABLE IF NOT EXISTS invitations (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    token TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_invitations_token ON invitations(token);
CREATE INDEX IF NOT EXISTS idx_invitations_org_id ON invitations(org_id);
