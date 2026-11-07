-- +goose Up

CREATE TABLE subscription_reminders (
    id BIGSERIAL PRIMARY KEY,
    subscription_id BIGINT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    renewal_date DATE NOT NULL,
    days_before SMALLINT NOT NULL CHECK (days_before IN (7, 2, 1)),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'processing', 'sent', 'failed')),
    resend_email_id TEXT,
    attempts SMALLINT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error TEXT,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_until TIMESTAMPTZ,
    sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_subscription_reminder
        UNIQUE (subscription_id, renewal_date, days_before)
);

CREATE INDEX idx_subscription_reminders_pending
    ON subscription_reminders (next_attempt_at, id)
    WHERE status IN ('pending', 'failed', 'processing');

-- +goose Down

DROP TABLE IF EXISTS subscription_reminders;
