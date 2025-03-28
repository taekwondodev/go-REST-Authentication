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
			http.Error(w, "Miss Token or not valid", http.StatusUnauthorized)
			return
		}

		jwt := config.JWT{}
		tokenString := strings.TrimPrefix(header, "Bearer ")
		claims, err := jwt.ValidateJWT(tokenString)
		if err != nil {
			http.Error(w, "Token not valid", http.StatusUnauthorized)
			return
		}

		// Check here later
		r.Header.Set("Username", claims.Username)
		next(w, r)
	}
}
