.PHONY: migrate-up migrate-down sqlc new-migration test-email run-reminder-worker

# Include .env if it exists and export its variables automatically
-include .env
export

migrate-up:
	@if [ -z "$(DATABASE_URL)" ]; then echo "DATABASE_URL is not configured"; exit 1; fi
	goose -dir db/migration postgres "$(DATABASE_URL)" up

migrate-down:
	@if [ -z "$(DATABASE_URL)" ]; then echo "DATABASE_URL is not configured"; exit 1; fi
	goose -dir db/migration postgres "$(DATABASE_URL)" down

sqlc:
	sqlc generate

new-migration:
	goose -dir db/migration create $(name) sql

test-email:
	go run ./cmd/test_email

run-reminder-worker:
	go run ./cmd/reminder_worker
