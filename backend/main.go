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
	authService := service.NewAuthService(authRepo)
	authController := controller.NewAuthController(authService)

	setupPublicRoutes(authController)

	log.Println("Server in ascolto sulla porta 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func setupPublicRoutes(authController *controller.AuthController) {
	http.HandleFunc("/register", authController.Register)
	http.HandleFunc("/login", authController.Login)
}

/*
func setupProtectedRoutes() {
	http.HandleFunc("/profile", middleware.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		username := r.Header.Get("Username")
		w.Write([]byte("Benvenuto " + username))
	}))
}
*/
