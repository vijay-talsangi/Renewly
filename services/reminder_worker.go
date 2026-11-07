package services

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	db "github.com/vijay-talsangi/Renewly/db/sqlc"
)

// ReminderWorker processes upcoming subscription renewal reminders.
type ReminderWorker struct {
	queries       *db.Queries
	email         *EmailService
	location      *time.Location
	batchSize     int
	maxAttempts   int
	testRecipient string
}

type dueReminder = db.ClaimReminderBatchRow

func NewReminderWorker(
	pool *pgxpool.Pool,
	email *EmailService,
	location *time.Location,
	batchSize int,
	maxAttempts int,
	testRecipient string,
) (*ReminderWorker, error) {
	if pool == nil {
		return nil, fmt.Errorf("database pool is required")
	}

	if email == nil {
		return nil, fmt.Errorf("email service is required")
	}

	if location == nil {
		return nil, fmt.Errorf("reminder timezone is required")
	}

	if batchSize < 1 || batchSize > 500 {
		return nil, fmt.Errorf("REMINDER_BATCH_SIZE must be between 1 and 500")
	}

	if maxAttempts < 1 || maxAttempts > 10 {
		return nil, fmt.Errorf("REMINDER_MAX_ATTEMPTS must be between 1 and 10")
	}

	return &ReminderWorker{
		queries:       db.New(pool),
		email:         email,
		location:      location,
		batchSize:     batchSize,
		maxAttempts:   maxAttempts,
		testRecipient: strings.TrimSpace(testRecipient),
	}, nil
}

// dateParam converts a calendar date into a PostgreSQL date parameter.
// UTC midnight preserves the intended calendar date when using pgtype.Date.
func dateParam(value time.Time) pgtype.Date {
	return pgtype.Date{
		Time: time.Date(
			value.Year(),
			value.Month(),
			value.Day(),
			0, 0, 0, 0,
			time.UTC,
		),
		Valid: true,
	}
}

// Run creates due reminder records and processes them until no work remains.
func (w *ReminderWorker) Run(ctx context.Context) error {
	now := time.Now().In(w.location)

	today := time.Date(
		now.Year(),
		now.Month(),
		now.Day(),
		0, 0, 0, 0,
		w.location,
	)

	date := dateParam(today)

	inserted, err := w.queries.CreateDueReminders(ctx, date)
	if err != nil {
		return fmt.Errorf("create due reminder records: %w", err)
	}

	log.Printf(
		"reminder worker: created %d reminder record(s) for %s",
		inserted,
		today.Format("2006-01-02"),
	)

	var sentCount int
	var failedCount int

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		batch, err := w.claimBatch(ctx, date)
		if err != nil {
			return fmt.Errorf("claim reminder batch: %w", err)
		}

		if len(batch) == 0 {
			waited, err := w.waitForRetry(ctx, date)
			if err != nil {
				return fmt.Errorf("wait for reminder retry: %w", err)
			}

			if waited {
				continue
			}

			break
		}

		for i, item := range batch {
			if err := ctx.Err(); err != nil {
				return err
			}

			if i > 0 {
				// Keep some spacing between Resend API requests.
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(600 * time.Millisecond):
				}
			}

			if err := w.sendOne(ctx, item); err != nil {
				failedCount++

				log.Printf(
					"reminder worker: reminder_id=%d attempt=%d failed: %v",
					item.ID,
					item.Attempts,
					err,
				)

				if markErr := w.markFailed(item.ID, err); markErr != nil {
					return fmt.Errorf(
						"mark reminder %d failed after send error %q: %w",
						item.ID,
						err,
						markErr,
					)
				}

				continue
			}

			sentCount++
		}
	}

	log.Printf(
		"reminder worker finished: sent=%d failed_or_retrying=%d",
		sentCount,
		failedCount,
	)

	return nil
}

// claimBatch atomically claims reminders using SELECT FOR UPDATE SKIP LOCKED.
func (w *ReminderWorker) claimBatch(
	ctx context.Context,
	today pgtype.Date,
) ([]dueReminder, error) {
	return w.queries.ClaimReminderBatch(
		ctx,
		db.ClaimReminderBatchParams{
			MaxAttempts: int16(w.maxAttempts),
			Today:       today,
			BatchSize:   int32(w.batchSize),
		},
	)
}

// waitForRetry waits until the next failed reminder becomes eligible.
func (w *ReminderWorker) waitForRetry(
	ctx context.Context,
	today pgtype.Date,
) (bool, error) {
	nextAttemptEpoch, err := w.queries.GetNextReminderRetry(
		ctx,
		db.GetNextReminderRetryParams{
			MaxAttempts: int16(w.maxAttempts),
			Today:       today,
		},
	)
	if err != nil {
		return false, err
	}

	if nextAttemptEpoch == 0 {
		return false, nil
	}

	delay := time.Until(time.Unix(nextAttemptEpoch, 0))

	if delay <= 0 {
		return true, nil
	}

	log.Printf(
		"reminder worker: waiting %s before retrying failed reminders",
		delay.Round(time.Second),
	)

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false, ctx.Err()

	case <-timer.C:
		return true, nil
	}
}

// sendOne sends one email and records the successful Resend response.
func (w *ReminderWorker) sendOne(
	ctx context.Context,
	item dueReminder,
) error {
	dueDate, err := time.ParseInLocation(
		"2006-01-02",
		item.RenewalDate,
		w.location,
	)
	if err != nil {
		return fmt.Errorf(
			"parse renewal date %q: %w",
			item.RenewalDate,
			err,
		)
	}

	recipient := item.UserEmail

	// Optional override for testing. Do not configure this in production.
	if w.testRecipient != "" {
		recipient = w.testRecipient
	}

	emailID, err := w.email.SendRenewalReminderWithIdempotencyKey(
		ctx,
		RenewalReminder{
			To:               recipient,
			UserName:         item.UserName,
			SubscriptionName: item.SubscriptionName,
			Amount:           item.Amount,
			Currency:         item.Currency,
			BillingCycle:     item.BillingCycle,
			DueDate:          dueDate,
			DaysUntilDue:     int(item.DaysBefore),
		},
		fmt.Sprintf("renewal-reminder/%d", item.ID),
	)
	if err != nil {
		return err
	}

	// Record success even if the job context is shutting down.
	// This matters because Resend may already have accepted the email.
	markCtx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	err = w.queries.MarkReminderSent(
		markCtx,
		db.MarkReminderSentParams{
			ResendEmailID: pgtype.Text{
				String: emailID,
				Valid:  true,
			},
			ID: item.ID,
		},
	)
	if err != nil {
		return fmt.Errorf("update sent reminder status: %w", err)
	}

	log.Printf(
		"reminder worker: sent reminder_id=%d resend_email_id=%s",
		item.ID,
		emailID,
	)

	return nil
}

// markFailed records the failure and schedules a retry.
// A separate context lets us update PostgreSQL during job shutdown.
func (w *ReminderWorker) markFailed(
	reminderID int64,
	sendErr error,
) error {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	return w.queries.MarkReminderFailed(
		ctx,
		db.MarkReminderFailedParams{
			ErrorMessage: sendErr.Error(),
			ID:           reminderID,
		},
	)
}
