package services

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/vijay-talsangi/Renewly/db/sqlc"
)

var (
	ErrSubscriptionNotFound = errors.New("subscription not found")
)

type CreateSubscriptionInput struct {
	UserID          int64           `json:"-" binding:"-"`
	Name            string          `json:"name" binding:"required"`
	Category        string          `json:"category" binding:"required"`
	Website         pgtype.Text     `json:"website"`
	Note            pgtype.Text     `json:"notes"`
	Amount          pgtype.Numeric  `json:"amount" binding:"required"`
	Currency        string          `json:"currency" binding:"required"`
	BillingCycle    db.BillingCycle `json:"billing_cycle" binding:"required"`
	AutoRenew       bool            `json:"auto_renew" binding:"required"`
	StartDate       pgtype.Date     `json:"start_date" binding:"required"`
	NextBillingDate pgtype.Date     `json:"next_billing_date" binding:"required"`
}

type SubscriptionService struct {
	q *db.Queries
}

func NewSubscriptionService(q *db.Queries) *SubscriptionService {
	return &SubscriptionService{q: q}
}

func (ss *SubscriptionService) CreateSubscription(ctx context.Context, input CreateSubscriptionInput) error {
	_, err := ss.q.CreateSubscription(ctx, db.CreateSubscriptionParams{
		UserID:          input.UserID,
		Name:            input.Name,
		Category:        input.Category,
		Website:         input.Website,
		Notes:           input.Note,
		Amount:          input.Amount,
		Currency:        input.Currency,
		BillingCycle:    input.BillingCycle,
		AutoRenew:       input.AutoRenew,
		StartDate:       input.StartDate,
		NextBillingDate: input.NextBillingDate,
	})

	return err
}
