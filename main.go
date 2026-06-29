package main

import (
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/vijay-talsangi/Renewly/config"
	"github.com/vijay-talsangi/Renewly/controllers"
	"github.com/vijay-talsangi/Renewly/services"
)

func main() {
	if err := godotenv.Load(); err != nil {
		panic("Error loading .env file")
	}

	config.ConnectDatabase()
	defer config.DBConfig.Close()

	r := gin.Default()

	userService := &services.UserService{}
	userController := controllers.NewUserController(userService)
	userController.RegisterRoutes(r)

	r.Run(":8080")
}
