package middleware

import (
	"backend/config"
	"net/http"
	"strings"
)

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")

		if header == "" || !strings.HasPrefix(header, "Bearer") {
			http.Error(w, "Token non valido o mancante", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(header, "Bearer ")
		claims, err := config.ValidateJWT(tokenString)
		if err != nil {
			http.Error(w, "Token non valido", http.StatusUnauthorized)
			return
		}

		// Check here later
		r.Header.Set("Username", claims.Username)
		next(w, r)
	}
}
