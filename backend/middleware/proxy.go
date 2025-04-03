package middleware

import "net/http"

func TrustProxyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Check if the request is coming from a trusted proxy
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			r.URL.Scheme = proto
		}

		// 2. Fix the host
		if host := r.Header.Get("X-Forwarded-Host"); host != "" {
			r.Host = host
		}

		// 3. Next handler
		next.ServeHTTP(w, r)
	})
}
