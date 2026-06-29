-- +goose Up

CREATE TYPE billing_cycle AS ENUM (
    'monthly',
    'yearly'
);

CREATE TYPE subscription_status AS ENUM (
    'active',
    'cancelled'
);

CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE subscriptions (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    amount NUMERIC(10,2) NOT NULL,
    currency CHAR(3) NOT NULL DEFAULT 'INR',
    billing_cycle billing_cycle NOT NULL,
    start_date DATE NOT NULL,
    next_billing_date DATE NOT NULL,
    auto_renew BOOLEAN NOT NULL DEFAULT TRUE,
    website TEXT,
    notes TEXT,
    status subscription_status NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_subscription_user ON subscriptions(user_id);
CREATE INDEX idx_next_billing ON subscriptions(next_billing_date);
CREATE INDEX idx_status ON subscriptions(status);

-- +goose Down

DROP TABLE IF EXISTS subscriptions;
DROP TABLE IF EXISTS users;

DROP TYPE IF EXISTS subscription_status;
DROP TYPE IF EXISTS billing_cycle;