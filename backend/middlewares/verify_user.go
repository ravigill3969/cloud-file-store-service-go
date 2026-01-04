package middleware

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ravigill3969/cloud-file-store/backend/utils"
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
				utils.RespondError(w, http.StatusUnauthorized, "Unauthorized: Authentication token required")
				return
			}
			log.Printf("Auth failed: Error reading cookie: %v", err)
			utils.RespondError(w, http.StatusBadRequest, "Bad Request")
			return
		}

		rcookie, err := r.Cookie("refresh_token")

		if err != nil {
			if err == http.ErrNoCookie {
				log.Println("Auth failed: No 'refresh_token' cookie found.")
				utils.RespondError(w, http.StatusUnauthorized, "Unauthorized: Authentication token required")
				return
			}
			log.Printf("Auth failed: Error reading cookie: %v", err)
			utils.RespondError(w, http.StatusBadRequest, "Bad Request")
			return
		}

		rTokenString := rcookie.Value

		tokenString := cookie.Value

		jwtKey := os.Getenv("ACCESS_JWT_ACCESS_TOKEN_SECRET")

		claims, err := utils.ParseToken(tokenString, []byte(jwtKey))
		if err != nil {
			log.Printf("Auth failed: Invalid or expired token: %v", err)
			utils.RespondError(w, http.StatusUnauthorized, "Unauthorized: Invalid or expired token")
			return
		}

		key := fmt.Sprintf("refresh:%s", string(claims.UserID))

		requestCtx := r.Context()
		redisOpCtx, cancel := context.WithTimeout(requestCtx, 5*time.Second)
		defer cancel()

		refreshTokenFromRedis, err := redis.RedisClient.Get(redisOpCtx, key).Result()

		if err != nil {
			utils.RespondError(w, http.StatusInternalServerError, "Something went incredibly wrong!")
			return
		}

		if refreshTokenFromRedis != rTokenString {
			utils.RespondError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		ctx := context.WithValue(r.Context(), UserIDContextKey, claims.UserID)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}
