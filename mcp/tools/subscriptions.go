// Package tools contains all tools for mcp
package tools

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
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
	sdk.AddTool(server, &sdk.Tool{
		Name:        "get_subscription",
		Description: "Get details of a specific subscription belonging to the authenticated Renewly user. Requires a subscription ID.",
	}, func(
		ctx context.Context,
		req *sdk.CallToolRequest,
		input struct {
			ID int64 `json:"id" jsonschema:"Subscription ID"`
		},
	) (*sdk.CallToolResult, SubscriptionOutput, error) {
		sub, err := queries.GetSubscription(ctx, db.GetSubscriptionParams{
			ID:     input.ID,
			UserID: userID,
		})
		if err != nil {
			return nil, SubscriptionOutput{}, err
		}

		output := SubscriptionOutput{
			ID:              sub.ID,
			Name:            sub.Name,
			Category:        sub.Category,
			Currency:        sub.Currency,
			BillingCycle:    string(sub.BillingCycle),
			AutoRenew:       sub.AutoRenew,
			Status:          string(sub.Status),
			StartDate:       dateString(sub.StartDate.Time, sub.StartDate.Valid),
			NextBillingDate: dateString(sub.NextBillingDate.Time, sub.NextBillingDate.Valid),
		}

		return nil, output, nil
	})
	sdk.AddTool(server, &sdk.Tool{
		Name:        "create_subscription",
		Description: "Create a subscription for the authenticated Renewly user. Amount must be a decimal string and dates must use YYYY-MM-DD format.",
	}, func(
		ctx context.Context,
		req *sdk.CallToolRequest,
		input struct {
			Name            string `json:"name" jsonschema:"Subscription name"`
			Category        string `json:"category" jsonschema:"Subscription category"`
			Amount          string `json:"amount" jsonschema:"Subscription amount as a decimal string"`
			Currency        string `json:"currency" jsonschema:"Currency code such as INR or USD"`
			BillingCycle    string `json:"billing_cycle" jsonschema:"Billing cycle"`
			AutoRenew       bool   `json:"auto_renew" jsonschema:"Whether subscription automatically renews"`
			StartDate       string `json:"start_date" jsonschema:"Start date in YYYY-MM-DD format"`
			NextBillingDate string `json:"next_billing_date" jsonschema:"Next billing date in YYYY-MM-DD format"`
			Website         string `json:"website" jsonschema:"Optional subscription website"`
			Notes           string `json:"notes" jsonschema:"Optional notes"`
		},
	) (*sdk.CallToolResult, map[string]any, error) {
		// Validate required text fields.
		if input.Name == "" || input.Category == "" ||
			input.Amount == "" || input.Currency == "" ||
			input.BillingCycle == "" {
			return nil, nil, fmt.Errorf("name, category, amount, currency and billing_cycle are required")
		}

		// Parse amount.
		var amount pgtype.Numeric
		if err := amount.Scan(input.Amount); err != nil {
			return nil, nil, fmt.Errorf("invalid amount: %w", err)
		}

		// Parse dates.
		startDate, err := time.Parse("2006-01-02", input.StartDate)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid start_date: use YYYY-MM-DD")
		}

		nextBillingDate, err := time.Parse("2006-01-02", input.NextBillingDate)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid next_billing_date: use YYYY-MM-DD")
		}

		if amount.NaN || amount.InfinityModifier != pgtype.Finite {
			return nil, nil, fmt.Errorf("amount must be a finite number")
		}

		if amount.Int == nil || amount.Int.Sign() <= 0 {
			return nil, nil, fmt.Errorf("amount must be greater than zero")
		}

		// Insert under the authenticated user, never a user ID supplied by the AI.
		sub, err := queries.CreateSubscription(ctx, db.CreateSubscriptionParams{
			UserID:          userID,
			Name:            input.Name,
			Category:        input.Category,
			Amount:          amount,
			Currency:        input.Currency,
			BillingCycle:    db.BillingCycle(input.BillingCycle),
			AutoRenew:       input.AutoRenew,
			StartDate:       pgtype.Date{Time: startDate, Valid: true},
			NextBillingDate: pgtype.Date{Time: nextBillingDate, Valid: true},
			Website:         pgtype.Text{String: input.Website, Valid: input.Website != ""},
			Notes:           pgtype.Text{String: input.Notes, Valid: input.Notes != ""},
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create subscription: %w", err)
		}

		return nil, map[string]any{
			"message":           "Subscription created successfully",
			"id":                sub.ID,
			"name":              sub.Name,
			"currency":          sub.Currency,
			"billing_cycle":     string(sub.BillingCycle),
			"next_billing_date": input.NextBillingDate,
		}, nil
	})
	sdk.AddTool(server, &sdk.Tool{
		Name:        "update_subscription",
		Description: "Update an existing subscription belonging to the authenticated Renewly user.",
	}, func(
		ctx context.Context,
		req *sdk.CallToolRequest,
		input struct {
			ID              int64  `json:"id" jsonschema:"Subscription ID"`
			Name            string `json:"name"`
			Category        string `json:"category"`
			Amount          string `json:"amount"`
			Currency        string `json:"currency"`
			BillingCycle    string `json:"billing_cycle"`
			AutoRenew       bool   `json:"auto_renew"`
			StartDate       string `json:"start_date"`
			NextBillingDate string `json:"next_billing_date"`
			Website         string `json:"website"`
			Notes           string `json:"notes"`
		},
	) (*sdk.CallToolResult, map[string]any, error) {
		if input.ID <= 0 {
			return nil, nil, fmt.Errorf("invalid subscription ID")
		}

		if input.Name == "" || input.Category == "" ||
			input.Currency == "" {
			return nil, nil, fmt.Errorf("name, category and currency are required")
		}

		amount, err := parseMCPAmount(input.Amount)
		if err != nil {
			return nil, nil, err
		}

		if input.BillingCycle != "monthly" && input.BillingCycle != "yearly" {
			return nil, nil, fmt.Errorf("billing_cycle must be monthly or yearly")
		}

		startDate, err := parseMCPDate(input.StartDate)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid start_date: %w", err)
		}

		nextDate, err := parseMCPDate(input.NextBillingDate)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid next_billing_date: %w", err)
		}

		sub, err := queries.UpdateSubscription(ctx, db.UpdateSubscriptionParams{
			ID:              input.ID,
			UserID:          userID,
			Name:            input.Name,
			Category:        input.Category,
			Amount:          amount,
			Currency:        input.Currency,
			BillingCycle:    db.BillingCycle(input.BillingCycle),
			AutoRenew:       input.AutoRenew,
			StartDate:       startDate,
			NextBillingDate: nextDate,
			Website:         pgtype.Text{String: input.Website, Valid: input.Website != ""},
			Notes:           pgtype.Text{String: input.Notes, Valid: input.Notes != ""},
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to update subscription: %w", err)
		}

		return nil, map[string]any{
			"message": "Subscription updated successfully",
			"id":      sub.ID,
			"name":    sub.Name,
		}, nil
	})
	sdk.AddTool(server, &sdk.Tool{
		Name:        "cancel_subscription",
		Description: "Cancel an active subscription belonging to the authenticated Renewly user. This changes its status to cancelled.",
	}, func(
		ctx context.Context,
		req *sdk.CallToolRequest,
		input struct {
			ID int64 `json:"id" jsonschema:"Subscription ID to cancel"`
		},
	) (*sdk.CallToolResult, map[string]any, error) {
		if input.ID <= 0 {
			return nil, nil, fmt.Errorf("invalid subscription ID")
		}

		rows, err := queries.CancelSubscription(ctx, db.CancelSubscriptionParams{
			ID:     input.ID,
			UserID: userID,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to cancel subscription: %w", err)
		}

		if rows == 0 {
			return nil, nil, fmt.Errorf("subscription not found or does not belong to you")
		}

		return nil, map[string]any{
			"message": "Subscription cancelled successfully",
			"id":      input.ID,
			"status":  "cancelled",
		}, nil
	})
	sdk.AddTool(server, &sdk.Tool{
		Name:        "get_upcoming_bills",
		Description: "Get active subscriptions with upcoming renewal dates for the authenticated Renewly user.",
	}, func(
		ctx context.Context,
		req *sdk.CallToolRequest,
		input struct {
			DaysAhead int32 `json:"days_ahead" jsonschema:"Number of days ahead to look, between 1 and 365"`
		},
	) (*sdk.CallToolResult, []map[string]any, error) {
		if input.DaysAhead < 1 || input.DaysAhead > 365 {
			return nil, nil, fmt.Errorf("days_ahead must be between 1 and 365")
		}

		bills, err := queries.ListUpcomingBills(ctx, db.ListUpcomingBillsParams{
			UserID:    userID,
			DaysAhead: input.DaysAhead,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get upcoming bills: %w", err)
		}

		result := make([]map[string]any, 0, len(bills))

		for _, bill := range bills {
			result = append(result, map[string]any{
				"id":            bill.ID,
				"name":          bill.Name,
				"category":      bill.Category,
				"amount":        bill.Amount,
				"currency":      bill.Currency,
				"billing_cycle": string(bill.BillingCycle),
				"next_billing_date": dateString(
					bill.NextBillingDate.Time,
					bill.NextBillingDate.Valid,
				),
			})
		}

		return nil, result, nil
	})
}

func dateString(value time.Time, valid bool) string {
	if !valid {
		return ""
	}
	return value.Format("2006-01-02")
}

func parseMCPAmount(value string) (pgtype.Numeric, error) {
	var amount pgtype.Numeric

	rational, ok := new(big.Rat).SetString(value)
	if !ok || rational.Sign() <= 0 {
		return amount, fmt.Errorf("amount must be a valid positive decimal number")
	}

	if err := amount.Scan(value); err != nil {
		return amount, fmt.Errorf("invalid amount: %w", err)
	}

	return amount, nil
}

func parseMCPDate(value string) (pgtype.Date, error) {
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		return pgtype.Date{}, fmt.Errorf("date must use YYYY-MM-DD format")
	}

	return pgtype.Date{
		Time:  parsed,
		Valid: true,
	}, nil
}
