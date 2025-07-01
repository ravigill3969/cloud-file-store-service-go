package routes

import (
	"net/http"

	"github.com/ravigill3969/cloud-file-store/handlers"
	middleware "github.com/ravigill3969/cloud-file-store/middlewares"
)

func RegisterUserRoutes(mux *http.ServeMux, uh *handlers.UserHandler) {
	mux.Handle("GET /api/users/get-user", middleware.AuthMiddleware(http.HandlerFunc(uh.GetUserInfo)))
	mux.Handle("POST /api/users/get-secret-key", middleware.AuthMiddleware(http.HandlerFunc(uh.GetSecretKey)))
	mux.HandleFunc("GET /api/users/logout", uh.Logout)
	mux.HandleFunc("POST /api/users/register", uh.Register)
	mux.HandleFunc("POST /api/users/login", uh.Login)
}
