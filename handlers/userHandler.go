package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
)

type UserHandler struct {
	DB *sql.DB
}

func (h *UserHandler) GetAllUsers(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Getting all users\n")
}
