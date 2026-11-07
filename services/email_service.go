package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"
)

const resendEmailsEndpoint = "https://api.resend.com/emails"

// EmailService handles transactional emails through Resend.
type EmailService struct {
	apiKey     string
	from       string
	httpClient *http.Client
	endpoint   string
}

// RenewalReminder contains the data required for a renewal email.
type RenewalReminder struct {
	To               string
	UserName         string
	SubscriptionName string
	Amount           string
	Currency         string
	BillingCycle     string
	DueDate          time.Time
	DaysUntilDue     int
}

type resendEmailRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html"`
	Text    string   `json:"text"`
}

type resendEmailResponse struct {
	ID string `json:"id"`
}

type resendErrorResponse struct {
	Message string `json:"message"`
	Name    string `json:"name"`
}

type reminderTemplateData struct {
	UserName         string
	SubscriptionName string
	Amount           string
	Currency         string
	BillingCycle     string
	DueDate          string
	Timing           string
}

// NewEmailService creates a new Resend email client.
func NewEmailService(apiKey, from string) (*EmailService, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, fmt.Errorf("RESEND_API_KEY is required")
	}

	if strings.TrimSpace(from) == "" {
		return nil, fmt.Errorf("EMAIL_FROM is required")
	}

	return &EmailService{
		apiKey: apiKey,
		from:   from,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		endpoint: resendEmailsEndpoint,
	}, nil
}

// SendRenewalReminder sends a subscription renewal reminder.
func (s *EmailService) SendRenewalReminder(
	ctx context.Context,
	reminder RenewalReminder,
) (string, error) {
	return s.SendRenewalReminderWithIdempotencyKey(ctx, reminder, "")
}

// SendRenewalReminderWithIdempotencyKey sends a reminder with an optional
// provider-side idempotency key. Resend retains idempotency keys for 24 hours.
func (s *EmailService) SendRenewalReminderWithIdempotencyKey(
	ctx context.Context,
	reminder RenewalReminder,
	idempotencyKey string,
) (string, error) {
	if strings.TrimSpace(reminder.To) == "" {
		return "", fmt.Errorf("recipient email is required")
	}

	if strings.TrimSpace(reminder.SubscriptionName) == "" {
		return "", fmt.Errorf("subscription name is required")
	}

	if reminder.DueDate.IsZero() {
		return "", fmt.Errorf("renewal due date is required")
	}

	if reminder.DaysUntilDue != 7 &&
		reminder.DaysUntilDue != 2 &&
		reminder.DaysUntilDue != 1 {
		return "", fmt.Errorf("unsupported reminder interval: %d", reminder.DaysUntilDue)
	}

	if reminder.UserName == "" {
		reminder.UserName = "there"
	}

	if reminder.Currency == "" {
		reminder.Currency = "INR"
	}

	var timing string

	if reminder.DaysUntilDue == 1 {
		timing = "tomorrow"
	} else {
		timing = fmt.Sprintf("in %d days", reminder.DaysUntilDue)
	}

	data := reminderTemplateData{
		UserName:         reminder.UserName,
		SubscriptionName: reminder.SubscriptionName,
		Amount:           reminder.Amount,
		Currency:         reminder.Currency,
		BillingCycle:     reminder.BillingCycle,
		DueDate:          reminder.DueDate.Format("2 January 2006"),
		Timing:           timing,
	}

	subject := fmt.Sprintf(
		"Your %s subscription renews %s!",
		reminder.SubscriptionName,
		timing,
	)

	// Generate HTML email.
	htmlTemplate, err := template.New("renewal").Parse(renewalHTMLTemplate)
	if err != nil {
		return "", fmt.Errorf("parse email template: %w", err)
	}

	var htmlBody bytes.Buffer

	if err := htmlTemplate.Execute(&htmlBody, data); err != nil {
		return "", fmt.Errorf("render HTML email: %w", err)
	}

	// Generate plain-text fallback.
	textBody := fmt.Sprintf(
		"Hi %s,\n\nYour %s subscription renews %s.\n\n"+
			"Subscription: %s\n"+
			"Amount: %s %s\n"+
			"Billing cycle: %s\n"+
			"Renewal date: %s\n\n"+
			"Make sure you're prepared for your upcoming payment.\n\n"+
			"Thanks,\nTeam Renewly",
		data.UserName,
		data.SubscriptionName,
		data.Timing,
		data.SubscriptionName,
		data.Currency,
		data.Amount,
		data.BillingCycle,
		data.DueDate,
	)
	payload := resendEmailRequest{
		From:    s.from,
		To:      []string{reminder.To},
		Subject: subject,
		HTML:    htmlBody.String(),
		Text:    textBody,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal email payload: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		s.endpoint,
		bytes.NewReader(body),
	)
	if err != nil {
		return "", fmt.Errorf("create Resend request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(idempotencyKey) != "" {
		if len(idempotencyKey) > 256 {
			return "", fmt.Errorf("idempotency key must be 256 characters or fewer")
		}
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("send email request: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read Resend response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiError resendErrorResponse

		if err := json.Unmarshal(responseBody, &apiError); err == nil &&
			apiError.Message != "" {
			return "", fmt.Errorf(
				"resend API error (%s): %s",
				resp.Status,
				apiError.Message,
			)
		}

		return "", fmt.Errorf(
			"resend API returned %s: %s",
			resp.Status,
			string(responseBody),
		)
	}

	var result resendEmailResponse

	if err := json.Unmarshal(responseBody, &result); err != nil {
		return "", fmt.Errorf("decode Resend response: %w", err)
	}

	if result.ID == "" {
		return "", fmt.Errorf("resend returned an empty email ID")
	}

	return result.ID, nil
}

const renewalHTMLTemplate = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>

<body style="
    margin: 0;
    padding: 30px;
    background-color: #f4f4f5;
    font-family: Arial, sans-serif;
    color: #18181b;
">

<div style="
    max-width: 560px;
    margin: auto;
    background: #ffffff;
    border-radius: 12px;
    padding: 30px;
">

    <h2 style="margin-top: 0;">Renewly</h2>

    <p>Hi {{.UserName}},</p>

    <h2>Your subscription is approaching renewal!</h2>

    <p>
        Your <strong>{{.SubscriptionName}}</strong>
        subscription renews <strong>{{.Timing}}</strong>.
    </p>

    <div style="
        background: #f4f4f5;
        border-radius: 8px;
        padding: 20px;
        margin: 25px 0;
    ">

        <h3 style="margin-top: 0;">
            {{.SubscriptionName}}
        </h3>

        <h1 style="margin-bottom: 20px;">
            {{.Currency}} {{.Amount}}
        </h1>

        <p>
            <strong>Billing cycle:</strong>
            {{.BillingCycle}}
        </p>

        <p>
            <strong>Renewal date:</strong>
            {{.DueDate}}
        </p>

    </div>

    <p>
        Make sure you're prepared for your upcoming payment.
    </p>

    <p>
        Thanks for using Renewly!
    </p>

    <hr style="border: 0; border-top: 1px solid #e4e4e7;">

    <p style="font-size: 12px; color: #71717a;">
        This is an automated subscription renewal reminder
        from Renewly.
    </p>

</div>

</body>
</html>
`
