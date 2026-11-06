package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"github.com/vijay-talsangi/Renewly/config"
	db "github.com/vijay-talsangi/Renewly/db/sqlc"
	"github.com/vijay-talsangi/Renewly/internal/server"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found; using environment variables")
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stop()

	pool, err := config.NewDatabasePool(ctx)
	if err != nil {
		log.Fatalf("Database initialization failed: %v", err)
	}
	defer pool.Close()

	log.Println("PostgreSQL connection pool initialized successfully!")

	queries := db.New(pool)
	router := server.SetupRouter(queries)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	httpServer := &http.Server{
		Addr:              ":" + port,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	serverErrors := make(chan error, 1)

	go func() {
		log.Printf("Renewly API listening on port %s", port)
		serverErrors <- httpServer.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Printf("HTTP server failed: %v", err)
		}

	case <-ctx.Done():
		log.Println("Shutdown signal received")

		shutdownCtx, cancel := context.WithTimeout(
			context.Background(),
			10*time.Second,
		)
		defer cancel()

		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("Graceful shutdown failed: %v", err)
			_ = httpServer.Close()
		}

		<-serverErrors
		log.Println("Renewly API stopped")
	}
}
