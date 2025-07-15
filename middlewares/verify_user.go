package middleware

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ravigill3969/cloud-file-store/utils"
	"github.com/redis/go-redis/v9"
)

type contextKey string

const UserIDContextKey contextKey = "userID"

type RedisStruct struct {
	RedisClient *redis.Client
}

func (redis *RedisStruct) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("access_token")

		if err != nil {
			if err == http.ErrNoCookie {
				fmt.Println(err)
				utils.SendError(w, http.StatusUnauthorized, "Unauthorized: Authentication token required")
				return
			}
			log.Printf("Auth failed: Error reading cookie: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		rcookie, err := r.Cookie("refresh_token")

		if err != nil {
			if err == http.ErrNoCookie {
				log.Println("Auth failed: No 'refresh_token' cookie found.")
				http.Error(w, "Unauthorized: Authentication token required", http.StatusUnauthorized)
				return
			}
			log.Printf("Auth failed: Error reading cookie: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		rTokenString := rcookie.Value

		tokenString := cookie.Value

		jwtKey := os.Getenv("ACCESS_JWT_ACCESS_TOKEN_SECRET")

		claims, err := utils.ParseToken(tokenString, []byte(jwtKey))
		if err != nil {
			log.Printf("Auth failed: Invalid or expired token: %v", err)
			http.Error(w, "Unauthorized: Invalid or expired token", http.StatusUnauthorized)
			return
		}

		key := fmt.Sprintf("refresh:" + claims.UserID)

		requestCtx := r.Context()
		redisOpCtx, cancel := context.WithTimeout(requestCtx, 5*time.Second)
		defer cancel()

		refreshTokenFromRedis, err := redis.RedisClient.Get(redisOpCtx, key).Result()

		if err != nil {
			http.Error(w, "Something went incredibly wrong!", http.StatusInternalServerError)
			return
		}

		if refreshTokenFromRedis != rTokenString {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), UserIDContextKey, claims.UserID)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}
