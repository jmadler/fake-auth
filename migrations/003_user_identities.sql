-- user_identities for social/federation linking
CREATE TABLE IF NOT EXISTS user_identities (
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    PRIMARY KEY (provider, provider_user_id),
    UNIQUE (user_id, provider),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_user_identities_user_id ON user_identities(user_id);

-- Social connections
INSERT INTO connections (id, name, strategy)
VALUES ('con_google', 'google-oauth2', 'google-oauth2'), ('con_github', 'github', 'github')
ON CONFLICT (id) DO NOTHING;
