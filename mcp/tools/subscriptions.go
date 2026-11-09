// Package tools contains all tools for mcp
package tools

import (
	"context"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	db "github.com/vijay-talsangi/Renewly/db/sqlc"
)

type SubscriptionOutput struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	Category        string `json:"category"`
	Currency        string `json:"currency"`
	BillingCycle    string `json:"billing_cycle"`
	AutoRenew       bool   `json:"auto_renew"`
	Status          string `json:"status"`
	StartDate       string `json:"start_date"`
	NextBillingDate string `json:"next_billing_date"`
}

func RegisterSubscriptionTools(
	server *sdk.Server,
	queries *db.Queries,
	userID int64,
) {
	sdk.AddTool(
		server,
		&sdk.Tool{
			Name:        "list_subscriptions",
			Description: "List all active subscriptions belonging to the authenticated Renewly user.",
		},
		func(
			ctx context.Context,
			req *sdk.CallToolRequest,
			input struct{},
		) (*sdk.CallToolResult, []SubscriptionOutput, error) {
			subscriptions, err := queries.ListSubscriptions(ctx, userID)
			if err != nil {
				return nil, nil, err
			}

			output := make([]SubscriptionOutput, 0, len(subscriptions))

			for _, sub := range subscriptions {
				output = append(output, SubscriptionOutput{
					ID:              sub.ID,
					Name:            sub.Name,
					Category:        sub.Category,
					Currency:        sub.Currency,
					BillingCycle:    string(sub.BillingCycle),
					AutoRenew:       sub.AutoRenew,
					Status:          string(sub.Status),
					StartDate:       dateString(sub.StartDate.Time, sub.StartDate.Valid),
					NextBillingDate: dateString(sub.NextBillingDate.Time, sub.NextBillingDate.Valid),
				})
			}

			return nil, output, nil
		},
	)
}

func dateString(value time.Time, valid bool) string {
	if !valid {
		return ""
	}
	return value.Format("2006-01-02")
}
