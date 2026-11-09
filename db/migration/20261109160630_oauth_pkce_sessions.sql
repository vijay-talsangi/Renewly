-- +goose Up

-- PKCE uses the authorization-code signature as its lookup key. Keep the
-- challenge in a separate table because oauth_sessions already has that
-- signature as its primary key for the authorization-code record.
CREATE TABLE oauth_pkce_sessions (
    signature TEXT PRIMARY KEY,
    payload JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX oauth_pkce_sessions_expiry_idx
    ON oauth_pkce_sessions (expires_at);

-- +goose Down

DROP TABLE IF EXISTS oauth_pkce_sessions;
