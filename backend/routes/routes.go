package routes

import (
	"backend/controller"
	"backend/middleware"
	"net/http"
)

func SetupRoutes(authController *controller.AuthController) {
	http.HandleFunc("/register", authController.Register)
	http.HandleFunc("/login", authController.Login)

	// esempio di enpoint protetto da authMiddleware e viene recuperato l'username dal claim
	http.HandleFunc("/profile", middleware.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		username := r.Header.Get("Username")
		w.Write([]byte("Benvenuto " + username))
	}))
}
