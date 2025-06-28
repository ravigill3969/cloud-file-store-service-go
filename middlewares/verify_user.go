package middleware

import (
	"context"
	"log"
	"net/http"

	"github.com/ravigill3969/cloud-file-store/utils"
)

type contextKey string

// UserIDContextKey is the key used to store the authenticated UserID in the request context.
const UserIDContextKey contextKey = "userID"

// mux.Handle("GET /api/users/get-user", middleware.AuthMiddleware(http.HandlerFunc(uh.GetUserInfo)))

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("access_token")
		if err != nil {
			if err == http.ErrNoCookie {
				log.Println("Auth failed: No 'access_token' cookie found.")
				http.Error(w, "Unauthorized: Authentication token required", http.StatusUnauthorized)
				return
			}
			log.Printf("Auth failed: Error reading cookie: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		tokenString := cookie.Value

		claims, err := utils.ParseToken(tokenString)
		if err != nil {
			log.Printf("Auth failed: Invalid or expired token: %v", err)
			http.Error(w, "Unauthorized: Invalid or expired token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), UserIDContextKey, claims.UserID)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}
