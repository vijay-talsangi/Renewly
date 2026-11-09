-- +goose Up

-- Short-lived, server-side storage for the original OAuth authorization
-- request. The browser only receives an opaque random token; the raw query
-- string (client_id, redirect_uri, scope, state, PKCE challenge, resource)
-- stays on the server. Rows are single-use and expire quickly.
CREATE TABLE oauth_authorization_continuations (
    token_hash TEXT PRIMARY KEY,
    purpose TEXT NOT NULL CHECK (purpose IN ('login', 'consent')),
    request_query TEXT NOT NULL,
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT oauth_authorization_continuations_purpose_user_check CHECK (
        (purpose = 'login' AND user_id IS NULL)
        OR (purpose = 'consent' AND user_id IS NOT NULL)
    )
);

CREATE INDEX oauth_authorization_continuations_expiry_idx
    ON oauth_authorization_continuations (expires_at);

CREATE INDEX oauth_authorization_continuations_active_idx
    ON oauth_authorization_continuations (token_hash, purpose)
    WHERE consumed_at IS NULL;

-- +goose Down

DROP TABLE IF EXISTS oauth_authorization_continuations;
