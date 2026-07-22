-- Index on audit_logs.created_at for efficient retention deletes
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
