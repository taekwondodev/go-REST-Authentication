package main

import (
	"backend/config"
	"backend/controller"
	"backend/repository"
	"backend/service"
	"log"
	"net/http"
)

func main() {
	config.LoadEnv()

	config.InitDB()
	defer config.CloseDB()

	authRepo := repository.NewUserRepository(config.Db)
	authService := service.NewAuthService(authRepo, &config.JWT{})
	authController := controller.NewAuthController(authService)

	setupPublicRoutes(authController)

	log.Println("Server listening on the port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func setupPublicRoutes(authController *controller.AuthController) {
	http.HandleFunc("/register", authController.Register)
	http.HandleFunc("/login", authController.Login)
	http.HandleFunc("/refresh", authController.Refresh)
}
