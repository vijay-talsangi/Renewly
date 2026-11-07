package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/vijay-talsangi/Renewly/config"
	"github.com/vijay-talsangi/Renewly/services"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found; using environment variables")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	locationName := envOrDefault("REMINDER_TIMEZONE", "Asia/Kolkata")
	location, err := time.LoadLocation(locationName)
	if err != nil {
		log.Fatalf("load reminder timezone %q: %v", locationName, err)
	}

	batchSize := intEnvOrDefault("REMINDER_BATCH_SIZE", 100)
	maxAttempts := intEnvOrDefault("REMINDER_MAX_ATTEMPTS", 5)

	pool, err := config.NewDatabasePool(ctx)
	if err != nil {
		log.Fatalf("initialize database: %v", err)
	}
	defer pool.Close()

	emailService, err := services.NewEmailService(
		strings.TrimSpace(os.Getenv("RESEND_API_KEY")),
		strings.TrimSpace(os.Getenv("EMAIL_FROM")),
	)
	if err != nil {
		log.Fatalf("initialize email service: %v", err)
	}

	worker, err := services.NewReminderWorker(
		pool,
		emailService,
		location,
		batchSize,
		maxAttempts,
		os.Getenv("REMINDER_TEST_TO"),
	)
	if err != nil {
		log.Fatalf("initialize reminder worker: %v", err)
	}

	jobCtx, cancel := context.WithTimeout(ctx, 25*time.Minute)
	defer cancel()

	log.Printf("starting Renewly reminder worker (timezone=%s, batch_size=%d, max_attempts=%d)",
		locationName, batchSize, maxAttempts)

	if err := worker.Run(jobCtx); err != nil {
		log.Fatalf("reminder worker failed: %v", err)
	}
	log.Println("reminder worker completed successfully")
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func intEnvOrDefault(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		log.Fatalf("invalid integer in %s: %v", name, err)
	}
	return parsed
}
