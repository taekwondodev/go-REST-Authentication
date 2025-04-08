package middleware

import (
	"log"
	"net/http"
	"time"
)

func LoggingMiddleware(next HandlerFunc) HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		start := time.Now()

		// Log della richiesta in entrata
		log.Printf("Started %s %s", r.Method, r.URL.Path)

		// Chiama l'handler
		err := next(w, r)

		// Log della risposta
		duration := time.Since(start)
		status := http.StatusOK
		if err != nil {
			if e, ok := err.(*Error); ok {
				status = e.Code
			} else {
				status = http.StatusInternalServerError
			}
		}

		log.Printf("Completed %s %s | Status: %d | Duration: %v",
			r.Method, r.URL.Path, status, duration)

		return err
	}
}
