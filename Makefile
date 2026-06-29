DB_URL=$(DATABASE_URL)

migrate-up:
	goose -dir db/migration postgres "$(DB_URL)" up

migrate-down:
	goose -dir db/migration postgres "$(DB_URL)" down

sqlc:
	sqlc generate

new-migration:
	goose -dir db/migration create $(name) sql