package main

import (
	"backend/config"
	"backend/controller"
	"backend/database"
	"backend/repository"
	"backend/routes"
	"backend/service"
	"log"
	"net/http"
)

func main() {
	config.LoadEnv()

	database.InitDB()
	defer database.CloseDB()

	authRepo := repository.NewUserRepository(database.Db)
	authService := service.NewAuthService(authRepo)
	authController := controller.NewAuthController(authService)

	routes.SetupRoutes(authController)

	log.Println("Server in ascolto sulla porta 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
