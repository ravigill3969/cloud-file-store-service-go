package middleware

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/ravigill3969/cloud-file-store/backend/utils"
	"github.com/redis/go-redis/v9"
)

const (
	maxRequests     = 100
	rateLimitWindow = 1 * time.Minute
)

func GlobalRateLimiter(redisClient *redis.Client) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := getIP(r)
			key := fmt.Sprintf("rate_limit:site:%s", ip)

			allowed, err := checkRateLimit(redisClient, key)

			if err != nil {
				utils.RespondError(w, http.StatusInternalServerError, "Internal Error")
				return
			}
			if !allowed {
				utils.RespondError(w, http.StatusTooManyRequests, "Too many requests, wait for one minute!")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func getIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func checkRateLimit(redisClient *redis.Client, key string) (bool, error) {
	ctx := context.Background()

	current, err := redisClient.Get(ctx, key).Int64()
	if err != nil && err != redis.Nil {
		return false, err
	}

	if current >= int64(maxRequests) {
		return false, nil
	}

	count, err := redisClient.Incr(ctx, key).Result()
	if err != nil {
		return false, err
	}

	if count == 1 {
		redisClient.Expire(ctx, key, rateLimitWindow)
	}

	return count <= int64(maxRequests), nil
}
