-- name: CreateDueReminders :execrows
INSERT INTO subscription_reminders (
    subscription_id,
    renewal_date,
    days_before
)
SELECT
    s.id,
    s.next_billing_date,
    offsets.days_before
FROM subscriptions AS s
CROSS JOIN (
    VALUES (7::smallint), (2::smallint), (1::smallint)
) AS offsets(days_before)
WHERE s.status = 'active'
  AND s.next_billing_date = sqlc.arg(today)::date + offsets.days_before
ON CONFLICT (subscription_id, renewal_date, days_before) DO NOTHING;


-- name: ClaimReminderBatch :many
WITH candidates AS (
    SELECT r.id
    FROM subscription_reminders AS r
    JOIN subscriptions AS s ON s.id = r.subscription_id
    WHERE r.attempts < sqlc.arg(max_attempts)::smallint
      AND r.next_attempt_at <= NOW()
      AND r.renewal_date = s.next_billing_date
      AND r.renewal_date >= sqlc.arg(today)::date
      AND s.status = 'active'
      AND (
          r.status IN ('pending', 'failed')
          OR (
              r.status = 'processing'
              AND COALESCE(
                  r.locked_until,
                  '-infinity'::timestamptz
              ) < NOW()
          )
      )
    ORDER BY r.next_attempt_at, r.id
    LIMIT sqlc.arg(batch_size)::int
    FOR UPDATE OF r SKIP LOCKED
),
claimed AS (
    UPDATE subscription_reminders AS r
    SET
        status = 'processing',
        attempts = r.attempts + 1,
        locked_until = NOW() + INTERVAL '35 minutes',
        updated_at = NOW()
    FROM candidates AS c
    WHERE r.id = c.id
    RETURNING
        r.id,
        r.subscription_id,
        r.renewal_date,
        r.days_before,
        r.attempts
)
SELECT
    claimed.id,
    claimed.subscription_id,
    claimed.renewal_date::text AS renewal_date,
    claimed.days_before,
    claimed.attempts,
    u.name AS user_name,
    u.email AS user_email,
    s.name AS subscription_name,
    s.amount::text AS amount,
    BTRIM(s.currency::text) AS currency,
    s.billing_cycle::text AS billing_cycle
FROM claimed
JOIN subscriptions AS s ON s.id = claimed.subscription_id
JOIN users AS u ON u.id = s.user_id
WHERE s.status = 'active'
  AND s.next_billing_date = claimed.renewal_date
ORDER BY claimed.id;


-- name: GetNextReminderRetry :one
SELECT COALESCE(
    EXTRACT(EPOCH FROM MIN(r.next_attempt_at))::bigint,
    0
)::bigint AS next_attempt_epoch
FROM subscription_reminders AS r
JOIN subscriptions AS s ON s.id = r.subscription_id
WHERE r.status = 'failed'
  AND r.attempts < sqlc.arg(max_attempts)::smallint
  AND r.renewal_date >= sqlc.arg(today)::date
  AND r.renewal_date = s.next_billing_date
  AND s.status = 'active';


-- name: MarkReminderSent :exec
UPDATE subscription_reminders
SET
    status = 'sent',
    resend_email_id = sqlc.arg(resend_email_id),
    sent_at = NOW(),
    locked_until = NULL,
    last_error = NULL,
    updated_at = NOW()
WHERE id = sqlc.arg(id)
  AND status = 'processing';


-- name: MarkReminderFailed :exec
UPDATE subscription_reminders
SET
    status = 'failed',
    last_error = LEFT(sqlc.arg(error_message), 2000),
    next_attempt_at = NOW() + CASE attempts
        WHEN 1 THEN INTERVAL '1 minute'
        WHEN 2 THEN INTERVAL '3 minutes'
        WHEN 3 THEN INTERVAL '5 minutes'
        ELSE INTERVAL '10 minutes'
    END,
    locked_until = NULL,
    updated_at = NOW()
WHERE id = sqlc.arg(id)
  AND status = 'processing';
