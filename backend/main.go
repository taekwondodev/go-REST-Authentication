package main

import (
	"backend/api"
	"backend/config"
	"backend/controller"
	"backend/repository"
	"backend/service"
)

func main() {
	db := config.NewPostgres()
	db.InitDB()
	defer db.CloseDB()

	authRepo := repository.NewUserRepository(db.Db)
	authService := service.NewAuthService(authRepo, config.NewJWT())
	authController := controller.NewAuthController(authService)

	router := api.SetupRoutes(authController)
	server := api.NewServer(":80", router)

	server.StartWithGracefulShutdown()
}
