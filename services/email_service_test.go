package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSendRenewalReminder(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("expected POST, got %s", r.Method)
			}

			if r.URL.Path != "/emails" {
				t.Errorf("expected /emails, got %s", r.URL.Path)
			}

			if r.Header.Get("Authorization") != "Bearer test-api-key" {
				t.Error("invalid authorization header")
			}

			var payload resendEmailRequest

			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("failed to decode request: %v", err)
				return
			}

			if payload.From != "Renewly <onboarding@resend.dev>" {
				t.Errorf("unexpected sender: %s", payload.From)
			}

			if len(payload.To) != 1 || payload.To[0] != "vijay@example.com" {
				t.Errorf("unexpected recipient: %v", payload.To)
			}

			if payload.Subject != "Your Netflix subscription renews in 7 days!" {
				t.Errorf("unexpected subject: %s", payload.Subject)
			}

			if !strings.Contains(payload.HTML, "Netflix") {
				t.Error("HTML body should contain subscription name")
			}

			if !strings.Contains(payload.Text, "Netflix") {
				t.Error("text body should contain subscription name")
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			_, _ = w.Write([]byte(`{"id":"email_test_123"}`))
		},
	))

	defer server.Close()

	service := &EmailService{
		apiKey:     "test-api-key",
		from:       "Renewly <onboarding@resend.dev>",
		httpClient: server.Client(),
		endpoint:   server.URL + "/emails",
	}

	emailID, err := service.SendRenewalReminder(
		context.Background(),
		RenewalReminder{
			To:               "vijay@example.com",
			UserName:         "Vijay",
			SubscriptionName: "Netflix",
			Amount:           "649.00",
			Currency:         "INR",
			BillingCycle:     "monthly",
			DueDate:          time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC),
			DaysUntilDue:     7,
		},
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if emailID != "email_test_123" {
		t.Errorf("expected email ID email_test_123, got %s", emailID)
	}
}

func TestSendRenewalReminderInvalidInterval(t *testing.T) {
	service := &EmailService{}

	_, err := service.SendRenewalReminder(
		context.Background(),
		RenewalReminder{
			To:               "vijay@example.com",
			SubscriptionName: "Netflix",
			DueDate:          time.Now(),
			DaysUntilDue:     3,
		},
	)

	if err == nil {
		t.Fatal("expected error for unsupported reminder interval")
	}
}

func TestSendRenewalReminderAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)

			_, _ = w.Write([]byte(
				`{"message":"Invalid sender address"}`,
			))
		},
	))

	defer server.Close()

	service := &EmailService{
		apiKey:     "test-api-key",
		from:       "invalid@example.com",
		httpClient: server.Client(),
		endpoint:   server.URL + "/emails",
	}

	_, err := service.SendRenewalReminder(
		context.Background(),
		RenewalReminder{
			To:               "vijay@example.com",
			SubscriptionName: "Netflix",
			DueDate:          time.Now(),
			DaysUntilDue:     2,
		},
	)

	if err == nil {
		t.Fatal("expected Resend API error")
	}

	if !strings.Contains(err.Error(), "Invalid sender address") {
		t.Errorf("unexpected error: %v", err)
	}
}
