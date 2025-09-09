package routes

import (
	"net/http"

	"github.com/ravigill3969/cloud-file-store/backend/handlers"
	middleware "github.com/ravigill3969/cloud-file-store/backend/middlewares"
	"github.com/redis/go-redis/v9"
)

func RegisterUserRoutes(mux *http.ServeMux, uh *handlers.UserHandler, redis *redis.Client) {
	authMw := &middleware.RedisStruct{
		RedisClient: redis,
	}

	mux.Handle("GET /api/users/get-user", authMw.AuthMiddleware((http.HandlerFunc(uh.GetUserInfo))))
	mux.Handle("POST /api/users/get-secret-key", authMw.AuthMiddleware((http.HandlerFunc(uh.GetSecretKey))))
	mux.Handle("PATCH /api/users/update-secret-key", authMw.AuthMiddleware((http.HandlerFunc(uh.UpdateSecretKey))))
	mux.Handle("PUT /api/users/update-password", authMw.AuthMiddleware((http.HandlerFunc(uh.UpdatePassword))))
	mux.Handle("PUT /api/users/update-user-info", authMw.AuthMiddleware((http.HandlerFunc(uh.UpdateUserInfo))))

	mux.HandleFunc("GET /api/users/logout", uh.Logout)
	mux.HandleFunc("POST /api/users/register", uh.Register)
	mux.HandleFunc("POST /api/users/login", uh.Login)
	mux.HandleFunc("GET /api/users/refresh-token", uh.RefreshTokenVerify)
}
