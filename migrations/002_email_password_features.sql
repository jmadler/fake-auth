-- Add email_verified to users (PostgreSQL 9.6+)
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='email_verified') THEN
        ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT FALSE;
    END IF;
END $$;

-- Password reset tokens
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Login attempts for brute-force lockout
CREATE TABLE IF NOT EXISTS login_attempts (
    identifier TEXT PRIMARY KEY,
    attempt_count INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
