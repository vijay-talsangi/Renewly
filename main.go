package main

import (
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/vijay-talsangi/Renewly/config"
	"github.com/vijay-talsangi/Renewly/controllers"
	db "github.com/vijay-talsangi/Renewly/db/sqlc"
	"github.com/vijay-talsangi/Renewly/services"
)

func main() {
	if err := godotenv.Load(); err != nil {
		panic("Error loading .env file")
	}

	config.ConnectDatabase()
	defer config.DBConfig.Close()

	queries := db.New(config.DBConfig)

	userService := services.NewUserService(queries)

	userController := controllers.NewUserController(userService)

	r := gin.Default()

	api := r.Group("/api")
	{
		api.POST("/register", userController.Register)
		api.POST("/login", userController.Login)
		api.POST("/logout", userController.Logout)
	}

	r.Run(":8080")
}
