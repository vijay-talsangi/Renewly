package integration

import (
	"context"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	"github.com/pressly/goose/v3"
	db "github.com/vijay-talsangi/Renewly/db/sqlc"
	"github.com/vijay-talsangi/Renewly/internal/server"
)

func setupTestApp(t *testing.T) *gin.Engine {
	t.Helper()
	if err := godotenv.Load("../.env"); err != nil {
		t.Log("No .env file found; using environment variables")
	}

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping integration test")
	}

	ctx := context.Background()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("failed to create PostgreSQL pool: %v", err)
	}

	t.Cleanup(pool.Close)

	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}

	// Goose uses database/sql. OpenDBFromPool lets Goose
	// use the same underlying PostgreSQL connection pool.
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()

	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("failed to set Goose dialect: %v", err)
	}

	// integration/ is one directory below the project root.
	if err := goose.Up(sqlDB, "../db/migration"); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	// Safe because we have explicitly checked the database name.
	_, err = pool.Exec(
		ctx,
		"TRUNCATE TABLE subscriptions, users RESTART IDENTITY CASCADE",
	)
	if err != nil {
		t.Fatalf("failed to clean test database: %v", err)
	}

	t.Setenv("JWT_SECRET", "renewly-integration-test-secret")

	gin.SetMode(gin.TestMode)

	queries := db.New(pool)
	router := server.SetupRouter(queries)

	return router
}

// Ensure the pgx import is available for explicit PostgreSQL types
// when extending integration helpers in this package.
var _ = pgx.ErrNoRows
