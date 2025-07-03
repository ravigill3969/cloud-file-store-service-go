package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	middleware "github.com/ravigill3969/cloud-file-store/middlewares"
	"github.com/ravigill3969/cloud-file-store/models"
	"github.com/ravigill3969/cloud-file-store/utils"
	"github.com/redis/go-redis/v9"
)

type UserHandler struct {
	DB          *sql.DB
	RedisClient *redis.Client
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

	accessJWTKey := os.Getenv("ACCESS_JWT_ACCESS_TOKEN_SECRET")

	tokenStringForAccess, err := utils.CreateToken(user.UUID.String(), 3, []byte(accessJWTKey))
	if err != nil {
		log.Printf("Error creating token during register: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	refreshJWTKey := os.Getenv("ACCESS_JWT_REFRESH_TOKEN_SECRET")

	tokenStringForRefresh, err := utils.CreateToken(user.UUID.String(), 10, []byte(refreshJWTKey))
	if err != nil {
		log.Printf("Error creating token during register: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	requestCtx := r.Context()
	redisOpCtx, cancel := context.WithTimeout(requestCtx, 5*time.Second)
	defer cancel()

	key := user.UUID.String() + ":refresh"
	err = h.RedisClient.Set(redisOpCtx, key, tokenStringForRefresh, 1*time.Hour).Err()
	if err != nil {
		log.Printf("Error saving refresh token to Redis: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	utils.SetAuthCookie(w, tokenStringForAccess, tokenStringForRefresh)

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

	accessJWTKey := os.Getenv("ACCESS_JWT_ACCESS_TOKEN_SECRET")

	tokenStringForAccess, err := utils.CreateToken(storedUser.UUID.String(), 3, []byte(accessJWTKey))
	if err != nil {
		log.Printf("Error creating token during register: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	refreshJWTKey := os.Getenv("ACCESS_JWT_REFRESH_TOKEN_SECRET")

	tokenStringForRefresh, err := utils.CreateToken(storedUser.UUID.String(), 10, []byte(refreshJWTKey))
	if err != nil {
		log.Printf("Error creating token during register: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	utils.SetAuthCookie(w, tokenStringForAccess, tokenStringForRefresh)

	requestCtx := r.Context()
	redisOpCtx, cancel := context.WithTimeout(requestCtx, 5*time.Second)
	defer cancel()

	key := "refresh:" + storedUser.UUID.String()
	err = h.RedisClient.Set(redisOpCtx, key, tokenStringForRefresh, 1*time.Hour).Err()
	if err != nil {
		log.Printf("Error saving refresh token to Redis: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

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

}

func (h *UserHandler) Logout(w http.ResponseWriter, r *http.Request) {

	logOutResponse := models.LogoutRes{
		Message: "Logged out successfully!",
		Status:  "ok",
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "tokenString",
		Expires:  time.Now().Add(-time.Hour),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	err := json.NewEncoder(w).Encode(logOutResponse)

	if err != nil {
		log.Printf("Error encoding logout response to JSON: %v", err)
		http.Error(w, "Failed to encode response after logout", http.StatusInternalServerError)
		return
	}
}

func (h *UserHandler) GetUserInfo(w http.ResponseWriter, r *http.Request) {

	userID, ok := r.Context().Value(middleware.UserIDContextKey).(string)

	if !ok {
		log.Printf("Error: User ID not found in context")
		http.Error(w, "Unauthorized: User ID not provided", http.StatusUnauthorized)
		return
	}

	row := h.DB.QueryRow("SELECT username, email, public_key, account_type, max_api_calls, storage_used_mb, storage_quota_mb FROM users WHERE uuid = $1", &userID)

	var user models.UserProfile

	err := row.Scan(
		&user.Username,
		&user.Email,
		&user.PublicKey,
		&user.AccountType,
		&user.MaxAPICall,
		&user.StorageUsedMB,
		&user.StorageQuotaMB,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("User not found for ID: %s", userID)
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			log.Printf("Database error while fetching user info for ID %s: %v", userID, err)
			http.Error(w, "Internal server error: Failed to retrieve user data", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(user); err != nil {
		log.Printf("Error encoding user info to JSON: %v", err)
	}
}

func (h *UserHandler) GetSecretKey(w http.ResponseWriter, r *http.Request) {
	var password models.Password

	if err := json.NewDecoder(r.Body).Decode(&password); err != nil {
		http.Error(w, "Password is required", http.StatusBadRequest)
		return
	}

	userId, ok := r.Context().Value(middleware.UserIDContextKey).(string)
	if !ok {
		log.Printf("Error: User ID not found in context")
		http.Error(w, "Unauthorized: User ID not provided", http.StatusUnauthorized)
		return
	}

	row := h.DB.QueryRow("SELECT username, password_hash, email, secret_key FROM users WHERE uuid = $1", &userId)

	var user models.UserForSecretKey
	if err := row.Scan(&user.Username, &user.PasswordHash, &user.Email, &user.SecretKey); err != nil {
		if err == sql.ErrNoRows {
			log.Printf("User not found for ID: %s", userId)
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			log.Printf("Database error while fetching user info for ID %s: %v", userId, err)
			http.Error(w, "Internal server error: Failed to retrieve user data", http.StatusInternalServerError)
		}
		return
	}

	if !utils.CheckPasswordHash(password.Password, user.PasswordHash) {
		http.Error(w, "Incorrect password", http.StatusUnauthorized)
		return
	}

	if err := json.NewEncoder(w).Encode(user.SecretKey); err != nil {
		log.Printf("Error encoding secret key to JSON: %v", err)
	}
}

func (h *UserHandler) RefreshTokenVerify(w http.ResponseWriter, r *http.Request) {
	refreshCookie, err := r.Cookie("refresh_token")

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

	tokenString := refreshCookie.Value

	refreshJWTKey := os.Getenv("ACCESS_JWT_REFRESH_TOKEN_SECRET")

	claims, err := utils.ParseToken(tokenString, []byte(refreshJWTKey))

	fmt.Println(refreshJWTKey)

	if err != nil {
		log.Printf("Invalid refresh token: %v", err)
		http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
		return
	}

	userID := claims.UserID

	accessJWTKey := os.Getenv("ACCESS_JWT_ACCESS_TOKEN_SECRET")

	accessToken, err := utils.CreateToken(userID, 24*time.Hour*3, []byte(accessJWTKey))
	if err != nil {
		log.Printf("Error creating token during refresh check access token: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	refreshToken, err := utils.CreateToken(userID, 24*time.Hour*3, []byte(refreshJWTKey))
	if err != nil {
		log.Printf("Error creating token during refresh check refresh token: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	utils.SetAuthCookie(w, accessToken, refreshToken)

	w.WriteHeader(http.StatusOK)
	w.Header().Add("Content-type", "application/json")

	utils.SendJSON(w, http.StatusOK, map[string]string{
		userID: userID,
	})

}

func (h *UserHandler) UpdateSecretKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SecretKey string `json:"secretKey"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Secret key is required", http.StatusBadRequest)
		return
	}

	userID, ok := r.Context().Value(middleware.UserIDContextKey).(string)
	if !ok {
		log.Printf("Error: User ID not found in context")
		http.Error(w, "Unauthorized: User ID not provided", http.StatusUnauthorized)
		return
	}

	row := h.DB.QueryRow("SELECT username, password_hash, email, secret_key FROM users WHERE uuid = $1", &userID)

	var user models.UserForSecretKey
	if err := row.Scan(&user.Username, &user.PasswordHash, &user.Email, &user.SecretKey); err != nil {
		if err == sql.ErrNoRows {
			log.Printf("User not found for ID: %s", userID)
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			log.Printf("Database error while fetching user info for ID %s: %v", userID, err)
			http.Error(w, "Internal server error: Failed to retrieve user data", http.StatusInternalServerError)
		}
		return
	}

	if user.SecretKey != body.SecretKey {
		http.Error(w, "Invalid secret key", http.StatusBadRequest)
		return
	}

	newSecretKey, err := utils.GenerateKey(32)

	if err != nil {
		http.Error(w, "Unable to create new secret key", http.StatusInternalServerError)
		return
	}

	_, err = h.DB.Exec(`UPDATE users SET secret_key = $1 WHERE uuid = $2`, &newSecretKey, &userID)

	if err != nil {
		http.Error(w, "Unable to update secret key", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Add("Content-type", "application/json")

	err = json.NewEncoder(w).Encode(map[string]string{
		"message": "Secret key updated",
	})
	if err != nil {
		log.Println("Failed to encode JSON response:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}
