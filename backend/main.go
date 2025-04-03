package main

import (
	"backend/config"
	"backend/controller"
	"backend/middleware"
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

	router := setupPublicRoutes(authController)
	server := &http.Server{
		Addr:    ":8080",
		Handler: middleware.TrustProxyMiddleware(router),
	}

	log.Println("Server listening on the port 8080...")
	log.Fatal(server.ListenAndServe())
}

func setupPublicRoutes(authController *controller.AuthController) *http.ServeMux {
	router := http.NewServeMux()
	// Auth Routes
	http.HandleFunc("/register", authController.Register)
	http.HandleFunc("/login", authController.Login)
	http.HandleFunc("/refresh", authController.Refresh)

	// System Routes
	http.HandleFunc("/healthz", authController.HealthCheck)

	return router
}
