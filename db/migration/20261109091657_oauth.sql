
-- +goose Up

-- OAuth clients registered to use Renewly.
CREATE TABLE oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_secret_hash BYTEA,
    redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    grant_types TEXT[] NOT NULL DEFAULT '{}',
    response_types TEXT[] NOT NULL DEFAULT '{}',
    scopes TEXT[] NOT NULL DEFAULT '{}',
    audience TEXT[] NOT NULL DEFAULT '{}',
    is_public BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Authorization codes, access tokens and refresh tokens.
-- Store Fosite signatures, never the original raw tokens.
CREATE TABLE oauth_sessions (
    signature TEXT PRIMARY KEY,
    token_type TEXT NOT NULL CHECK (
        token_type IN (
            'authorization_code',
            'access_token',
            'refresh_token'
        )
    ),
    request_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    access_signature TEXT,
    payload JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    invalidated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX oauth_sessions_request_id_idx
    ON oauth_sessions (request_id);

CREATE INDEX oauth_sessions_active_lookup_idx
    ON oauth_sessions (signature, token_type)
    WHERE invalidated_at IS NULL AND revoked_at IS NULL;

CREATE INDEX oauth_sessions_expiry_idx
    ON oauth_sessions (expires_at);

CREATE INDEX oauth_sessions_access_signature_idx
    ON oauth_sessions (access_signature)
    WHERE access_signature IS NOT NULL;

-- Prevent replay of client assertion JWT IDs.
CREATE TABLE oauth_client_assertions (
    jti TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX oauth_client_assertions_expiry_idx
    ON oauth_client_assertions (expires_at);


-- +goose Down

DROP TABLE IF EXISTS oauth_client_assertions;
DROP TABLE IF EXISTS oauth_sessions;
DROP TABLE IF EXISTS oauth_clients;

