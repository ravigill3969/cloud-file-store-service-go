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

	"github.com/lib/pq"
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
		utils.SendError(w, http.StatusBadRequest, "Invalid req body")
		return
	}

	fmt.Println(user.Username)
	fmt.Println(user.Email)
	fmt.Println(user.PasswordHash)

	if user.Username == "" || user.Email == "" || user.PasswordHash == "" {
		utils.SendError(w, http.StatusBadRequest, "username, email and password are required")
		return
	}

	passwordHash, err := utils.HashPassword(user.PasswordHash)

	if err != nil {
		log.Printf("Error while hashing password: %v", err)
		utils.SendError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	publicKey, err := utils.GenerateKey(16)
	if err != nil {
		log.Printf("Error generating public key: %v", err)
		utils.SendError(w, http.StatusInternalServerError, "Internal Server Error")

		return
	}

	secretKey, err := utils.GenerateKey(32)
	if err != nil {
		log.Printf("Error generating secret key: %v", err)
		utils.SendError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	err = h.DB.QueryRow(`
    INSERT INTO users (username, email, password_hash, public_key, secret_key)
    VALUES ($1, $2, $3, $4, $5)
    RETURNING uuid
`, user.Username, user.Email, passwordHash, publicKey, secretKey).Scan(&user.UUID)

	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			log.Printf("Unique violation: %v", err)
			utils.SendError(w, http.StatusInternalServerError, "Email or username already in use!")
			return
		}
		log.Printf("Unexpected DB error: %v", err)
		utils.SendError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	accessJWTKey := os.Getenv("ACCESS_JWT_ACCESS_TOKEN_SECRET")

	tokenStringForAccess, err := utils.CreateToken(user.UUID.String(), 3, []byte(accessJWTKey))
	if err != nil {
		log.Printf("Error creating token during register: %v", err)
		utils.SendError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	refreshJWTKey := os.Getenv("ACCESS_JWT_REFRESH_TOKEN_SECRET")

	tokenStringForRefresh, err := utils.CreateToken(user.UUID.String(), 10, []byte(refreshJWTKey))
	if err != nil {
		log.Printf("Error creating token during register: %v", err)
		utils.SendError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	requestCtx := r.Context()
	redisOpCtx, cancel := context.WithTimeout(requestCtx, 5*time.Second)
	defer cancel()

	key := user.UUID.String() + ":refresh"
	err = h.RedisClient.Set(redisOpCtx, key, tokenStringForRefresh, 1*time.Hour).Err()
	if err != nil {
		log.Printf("Error saving refresh token to Redis: %v", err)
		utils.SendError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	utils.SetAuthCookie(w, tokenStringForAccess, tokenStringForRefresh)

	w.WriteHeader(http.StatusCreated)

	utils.SendJSON(w, http.StatusOK)
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
	err = h.RedisClient.Set(redisOpCtx, key, tokenStringForRefresh, 24*time.Hour).Err()
	if err != nil {
		log.Printf("Error saving refresh token to Redis: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)

	utils.SendJSON(w, http.StatusOK)

}

func (h *UserHandler) Logout(w http.ResponseWriter, r *http.Request) {

	redisCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)

	defer cancel()

	userId, ok := r.Context().Value(middleware.UserIDContextKey).(string)

	if !ok {
		log.Printf("Error: User ID not found in context")
		http.Error(w, "Unauthorized: User ID not provided", http.StatusUnauthorized)
		return
	}

	redisKey := fmt.Sprintf("refresh:" + userId)
	err := h.RedisClient.Del(redisCtx, redisKey).Err()

	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

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

	err = json.NewEncoder(w).Encode(logOutResponse)

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

	row := h.DB.QueryRow("SELECT uuid, username, email, public_key, account_type, post_api_calls, get_api_calls, edit_api_calls,created_at FROM users WHERE uuid = $1", &userID)

	var user models.UserProfile

	err := row.Scan(
		&user.Uuid,
		&user.Username,
		&user.Email,
		&user.PublicKey,
		&user.AccountType,
		&user.PostAPICalls,
		&user.GetAPICalls,
		&user.EditAPICalls,
		&user.CreatedAt,
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

	utils.SendJSON(w, http.StatusOK, user)
}

func (h *UserHandler) GetSecretKey(w http.ResponseWriter, r *http.Request) {
	var password models.Password

	if err := json.NewDecoder(r.Body).Decode(&password); err != nil {
		fmt.Println(err)
		utils.SendError(w, http.StatusBadRequest, "Password is required")
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

	utils.SendJSON(w, http.StatusOK, user.SecretKey)
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

	refreshToken, err := utils.CreateToken(userID, 24*time.Hour*30, []byte(refreshJWTKey))
	if err != nil {
		log.Printf("Error creating token during refresh check refresh token: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	redisCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)

	defer cancel()

	redisKey := fmt.Sprintf("refresh:" + userID)

	err = h.RedisClient.Set(redisCtx, redisKey, refreshToken, 24*time.Hour*30).Err()

	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
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

func (h *UserHandler) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	err := updateUserPasswordLogic(h.DB, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Password updated successfully"))
}

func updateUserPasswordLogic(db *sql.DB, r *http.Request) error {
	type Body struct {
		Password           string `json:"password"`
		NewPassword        string `json:"new_password"`
		ConfirmNewPassword string `json:"confirm_new_password"`
	}

	var body Body
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return fmt.Errorf("invalid request body")
	}

	if body.NewPassword != body.ConfirmNewPassword {
		return fmt.Errorf("new password and confirmation do not match")
	}

	userId, ok := r.Context().Value(middleware.UserIDContextKey).(string)
	if !ok {
		return fmt.Errorf("unauthorized")
	}

	var hashedPassword string
	err := db.QueryRow(`SELECT password_hash FROM users WHERE uuid = $1`, userId).Scan(&hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("user not found")
		}
		return fmt.Errorf("internal server error")
	}

	if !utils.CheckPasswordHash(body.Password, hashedPassword) {
		return fmt.Errorf("current password is incorrect")
	}

	newHashedPassword, err := utils.HashPassword(body.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash new password")
	}

	_, err = db.Exec(`UPDATE users SET password_hash = $1 WHERE uuid = $2`, newHashedPassword, userId)
	if err != nil {
		return fmt.Errorf("failed to update password")
	}

	return nil
}
