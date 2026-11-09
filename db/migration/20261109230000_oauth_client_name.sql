-- +goose Up

-- Dynamic client registration already accepts client_name. Persist it so the
-- consent screen can show the application's registered display name instead
-- of exposing the opaque client_id. Existing clients keep an empty name and
-- fall back to a generic label.
ALTER TABLE oauth_clients
    ADD COLUMN client_name TEXT NOT NULL DEFAULT '';

-- +goose Down

ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS client_name;
