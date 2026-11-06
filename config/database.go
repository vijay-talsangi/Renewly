package config

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func poolLimit(name string, fallback int32, allowZero bool) (int32, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil || parsed < 0 || (!allowZero && parsed == 0) {
		return 0, fmt.Errorf("invalid value for %s", name)
	}

	return int32(parsed), nil
}

func NewDatabasePool(ctx context.Context) (*pgxpool.Pool, error) {
	dsn := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if dsn == "" {
		return nil, fmt.Errorf("DATABASE_URL is not configured")
	}

	maxConns, err := poolLimit("DB_POOL_MAX_CONNS", 5, false)
	if err != nil {
		return nil, err
	}

	minConns, err := poolLimit("DB_POOL_MIN_CONNS", 0, true)
	if err != nil {
		return nil, err
	}

	if minConns > maxConns {
		return nil, fmt.Errorf("DB_POOL_MIN_CONNS cannot exceed DB_POOL_MAX_CONNS")
	}

	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}

	poolConfig.MaxConns = maxConns
	poolConfig.MinConns = minConns
	poolConfig.MaxConnLifetime = time.Hour
	poolConfig.MaxConnIdleTime = 30 * time.Minute
	poolConfig.HealthCheckPeriod = time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create database pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database ping failed: %w", err)
	}

	return pool, nil
}
