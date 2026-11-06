package main

import (
	"log"
	"os"

	"github.com/joho/godotenv"

	"github.com/vijay-talsangi/Renewly/config"
	db "github.com/vijay-talsangi/Renewly/db/sqlc"
	"github.com/vijay-talsangi/Renewly/internal/server"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found; using environment variables")
	}

	config.ConnectDatabase()
	defer config.DBConfig.Close()

	queries := db.New(config.DBConfig)
	router := server.SetupRouter(queries)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
