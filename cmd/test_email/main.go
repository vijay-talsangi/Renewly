package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/vijay-talsangi/Renewly/services"
)

func main() {
	// Load environment variables from project root.
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found; using environment variables")
	}

	apiKey := strings.TrimSpace(os.Getenv("RESEND_API_KEY"))
	from := strings.TrimSpace(os.Getenv("EMAIL_FROM"))
	recipient := strings.TrimSpace(os.Getenv("RESEND_TEST_TO"))

	if apiKey == "" {
		log.Fatal("RESEND_API_KEY is required")
	}

	if recipient == "" {
		log.Fatal("RESEND_TEST_TO is required")
	}

	// Resend's default test sender.
	if from == "" {
		from = "Renewly <onboarding@resend.dev>"
	}

	emailService, err := services.NewEmailService(apiKey, from)
	if err != nil {
		log.Fatalf("Failed to initialize email service: %v", err)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		20*time.Second,
	)
	defer cancel()

	// Sample subscription reminder.
	reminder := services.RenewalReminder{
		To:               recipient,
		UserName:         "Vijay",
		SubscriptionName: "Netflix",
		Amount:           "649.00",
		Currency:         "INR",
		BillingCycle:     "monthly",
		DueDate:          time.Now().AddDate(0, 0, 7),
		DaysUntilDue:     7,
	}

	fmt.Println("Sending test renewal reminder...")

	emailID, err := emailService.SendRenewalReminder(ctx, reminder)
	if err != nil {
		log.Fatalf("Failed to send email: %v", err)
	}

	fmt.Println("Email accepted by Resend successfully!")
	fmt.Println("Resend Email ID:", emailID)
}
