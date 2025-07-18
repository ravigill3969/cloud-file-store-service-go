package routes

import (
	"net/http"

	"github.com/ravigill3969/cloud-file-store/handlers"
	middleware "github.com/ravigill3969/cloud-file-store/middlewares"
	"github.com/redis/go-redis/v9"
)

func StripeRoutes(mux *http.ServeMux, s *handlers.Stripe, redis *redis.Client) {
	authMw := &middleware.RedisStruct{
		RedisClient: redis,
	}
	mux.Handle("POST /api/stripe/create-session", authMw.AuthMiddleware(http.HandlerFunc(s.CreateCheckoutSession)))
	// mux.Handle("POST /api/stripe/verify-session", authMw.AuthMiddleware(http.HandlerFunc(s.VerifyCheckoutSession)))
}
