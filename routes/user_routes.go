package routes

import (
	"net/http"

	"github.com/ravigill3969/cloud-file-store/handlers"
)

func RegisterUserRoutes(mux *http.ServeMux, uh *handlers.UserHandler) {
	// mux.HandleFunc("GET /api/users", uh.GetAllUsers)
	// mux.HandleFunc("GET /api/users/{id}", uh.GetUserByID)
	mux.HandleFunc("POST /api/users/register", uh.Register)
	mux.HandleFunc("POST /api/users/login", uh.Login)
	// mux.HandleFunc("PUT /api/users/{id}", uh.UpdateUser)
	// mux.HandleFunc("DELETE /api/users/{id}", uh.DeleteUser)
}
