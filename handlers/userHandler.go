package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/ravigill3969/cloud-file-store/models"
	"github.com/ravigill3969/cloud-file-store/utils"
)

type UserHandler struct {
	DB *sql.DB
}

func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	var user models.User

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		log.Printf("Error decoding request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if user.Username == "" || user.Email == "" || user.PasswordHash == "" {
		http.Error(w, "username , email , password are required", http.StatusBadRequest)
		return
	}

	passwordHash, err := utils.HashPassword(user.PasswordHash)

	if err != nil {
		log.Printf("Error while hashing password: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	publicKey, err := utils.GenerateKey(16)
	if err != nil {
		log.Printf("Error generating public key: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	secretKey, err := utils.GenerateKey(32)
	if err != nil {
		log.Printf("Error generating secret key: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	fmt.Println("Public Key:", publicKey)
	fmt.Println("Secret Key:", secretKey)

	err = h.DB.QueryRow(`
    INSERT INTO users (username, email, password_hash, public_key, secret_key)
    VALUES ($1, $2, $3, $4, $5)
    RETURNING uuid
`, user.Username, user.Email, passwordHash, publicKey, secretKey).Scan(&user.UUID)

	if err != nil {
		log.Printf("Error while saving user: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	safeUser := models.SafeUser{
		Username:  user.Username,
		UUID:      user.UUID,
		Email:     user.Email,
		PublicKey: publicKey,
	}

	token, err := utils.CreateToken(user.UUID.String())

	if err != nil {
		log.Printf("Error while creating token: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	utils.SetAuthCookie(w, token)

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(&safeUser); err != nil {
		log.Printf("Error encoding registered user to JSON: %v", err)
		http.Error(w, "Failed to encode response after registration", http.StatusInternalServerError)
		return
	}

	fmt.Printf("User registered successfully: %s (%s)\n", user.Username, user.UUID)
}

func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	var loginForm models.LoginForm
	if err := json.NewDecoder(r.Body).Decode(&loginForm); err != nil {
		log.Printf("Error decoding login request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if loginForm.Password == "" || (loginForm.Username == "" && loginForm.Email == "") {
		http.Error(w, "username/email and password are required", http.StatusBadRequest)
		return
	}

	var storedUser models.User
	var query string
	var args []interface{}

	if loginForm.Username != "" {
		query = "SELECT uuid, password_hash FROM users WHERE username = $1"
		args = []interface{}{loginForm.Username}
	} else {
		query = "SELECT uuid, password_hash FROM users WHERE email = $1"
		args = []interface{}{loginForm.Email}
	}

	err := h.DB.QueryRow(query, args...).Scan(
		&storedUser.UUID,
		&storedUser.PasswordHash,
	)

	if err == sql.ErrNoRows {
		log.Printf("Login attempt failed: User not found for username/email: %s %s", loginForm.Username, loginForm.Email)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	if err != nil {
		log.Printf("Error querying user for login: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if !utils.CheckPasswordHash(loginForm.Password, storedUser.PasswordHash) {
		log.Printf("Login attempt failed: Password mismatch for user %s", storedUser.Username)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	tokenString, err := utils.CreateToken(storedUser.UUID.String())
	if err != nil {
		log.Printf("Error creating token during login: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	utils.SetAuthCookie(w, tokenString)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	safeUserResponse := models.LoginRes{
		Message: "Logged in successfully!",
		Status:  "ok",
	}

	if err := json.NewEncoder(w).Encode(safeUserResponse); err != nil {
		log.Printf("Error encoding login response to JSON: %v", err)
		http.Error(w, "Failed to encode response after login", http.StatusInternalServerError)
		return
	}

	fmt.Printf("User %s (UUID: %s) logged in successfully.\n", storedUser.Username, storedUser.UUID.String())
}
