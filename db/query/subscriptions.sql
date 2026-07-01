-- name: CreateSubscription :one
INSERT INTO subscriptions (
    user_id,
    name,
    category,
    amount,
    currency,
    billing_cycle,
    start_date,
    next_billing_date,
    auto_renew,
    website,
    notes
)
VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11
)
RETURNING *;

-- name: GetSubscription :one
SELECT *
FROM subscriptions
WHERE id=$1;

-- name: ListSubscriptions :many
SELECT *
FROM subscriptions
WHERE user_id=$1
AND status='active'
ORDER BY next_billing_date;

-- name: UpdateSubscription :one
UPDATE subscriptions
SET
name=$2,
category=$3,
amount=$4,
currency=$5,
billing_cycle=$6,
start_date=$7,
next_billing_date=$8,
auto_renew=$9,
website=$10,
notes=$11,
updated_at=NOW()
WHERE id=$1
RETURNING *;

-- name: CancelSubscription :exec
UPDATE subscriptions
SET
status='cancelled',
updated_at=NOW()
WHERE id=$1;