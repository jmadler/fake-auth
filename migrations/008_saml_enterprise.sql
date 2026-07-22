-- SAML IdP: Service Providers that auth2 acts as IdP for
CREATE TABLE IF NOT EXISTS saml_service_providers (
    id TEXT PRIMARY KEY,
    entity_id TEXT NOT NULL UNIQUE,
    acs_url TEXT NOT NULL,
    certificate TEXT,
    metadata_url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_saml_sp_entity_id ON saml_service_providers(entity_id);

-- OIDC enterprise connections: generic IdP connectors (Okta, Azure AD, etc.)
-- Separate from org-scoped enterprise_connections in 007
CREATE TABLE IF NOT EXISTS oidc_enterprise_connections (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    issuer_url TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    scope TEXT DEFAULT 'openid email profile',
    domain_hint TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_oidc_enterprise_conn_name ON oidc_enterprise_connections(name);
