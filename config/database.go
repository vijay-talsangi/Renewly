package config

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

var DBConfig *pgxpool.Pool

func ConnectDatabase() {
	dsn := fmt.Sprintf("%s",
		os.Getenv("DATABASE_URL"),
	)

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Fatalf("Unable to connect to database pool: %v\n", err)
	}

	// Verify the connection is active
	if err := pool.Ping(context.Background()); err != nil {
		log.Fatalf("Database ping failed: %v\n", err)
	}

	DBConfig = pool
	log.Println("PostgreSQL connection pool initialized via pgx successfully!")
}
