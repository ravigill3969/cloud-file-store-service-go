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
	middleware "github.com/ravigill3969/cloud-file-store/backend/middlewares"
	"github.com/ravigill3969/cloud-file-store/backend/models"
	"github.com/ravigill3969/cloud-file-store/backend/utils"
	"github.com/redis/go-redis/v9"
)

type UserHandler struct {
	DB          *sql.DB
	RedisClient *redis.Client
}

func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.Body)
	var user models.User

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		log.Printf("Error decoding request body: %v", err)
		utils.RespondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if user.Username == "" || user.Email == "" || user.PasswordHash == "" {
		fmt.Println("Missing required fields")
		utils.RespondValidationError(w, "Missing required fields", []string{"username", "email", "password"})
		return
	}

	passwordHash, err := utils.HashPassword(user.PasswordHash)
	fmt.Println(err)
	fmt.Println(passwordHash)

	if err != nil {
		log.Printf("Error while hashing password: %v", err)
		utils.RespondInternal(w, err, "Could not process password")
		return
	}

	publicKey, err := utils.GenerateKey(16)
	fmt.Println(err)
	if err != nil {
		log.Printf("Error generating public key: %v", err)
		utils.RespondInternal(w, err, "Could not generate keys")

		return
	}

	secretKey, err := utils.GenerateKey(32)
	fmt.Println(err)
	if err != nil {
		log.Printf("Error generating secret key: %v", err)
		utils.RespondInternal(w, err, "Could not generate keys")
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
			utils.RespondError(w, http.StatusConflict, "Email or username already in use")
			return
		}
		log.Printf("Unexpected DB error: %v", err)
		utils.RespondInternal(w, err, "Unable to create account")
		return
	}

	accessJWTKey := os.Getenv("ACCESS_JWT_ACCESS_TOKEN_SECRET")

	tokenStringForAccess, err := utils.CreateToken(user.UUID.String(), 3, []byte(accessJWTKey))
	fmt.Println(err)
	if err != nil {
		log.Printf("Error creating token during register: %v", err)
		utils.RespondInternal(w, err, "Could not create session")
		return
	}

	refreshJWTKey := os.Getenv("ACCESS_JWT_REFRESH_TOKEN_SECRET")

	tokenStringForRefresh, err := utils.CreateToken(user.UUID.String(), 10, []byte(refreshJWTKey))
	fmt.Println(err)
	if err != nil {
		log.Printf("Error creating token during register: %v", err)
		utils.RespondInternal(w, err, "Could not create session")
		return
	}
	fmt.Println(err)

	requestCtx := r.Context()
	redisOpCtx, cancel := context.WithTimeout(requestCtx, 5*time.Second)
	defer cancel()

	key := user.UUID.String() + ":refresh"
	err = h.RedisClient.Set(redisOpCtx, key, tokenStringForRefresh, 1*time.Hour).Err()
	fmt.Println(err)
	if err != nil {
		log.Printf("Error saving refresh token to Redis: %v", err)
		utils.RespondInternal(w, err, "Could not persist session")
		return
	}

	utils.SetAuthCookie(w, tokenStringForAccess, tokenStringForRefresh)

	utils.RespondSuccess(w, http.StatusOK)
}

func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	var loginForm models.LoginForm
	if err := json.NewDecoder(r.Body).Decode(&loginForm); err != nil {
		log.Printf("Error decoding login request body: %v", err)
		utils.RespondError(w, http.StatusBadRequest, "Invalid login payload")
		return
	}

	if loginForm.Password == "" || (loginForm.Username == "" && loginForm.Email == "") {
		utils.RespondValidationError(w, "username/email and password are required", []string{"username_or_email", "password"})
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
		utils.RespondError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}
	if err != nil {
		utils.RespondInternal(w, err, "Unable to process login")
		return
	}

	if !utils.CheckPasswordHash(loginForm.Password, storedUser.PasswordHash) {
		log.Printf("Login attempt failed: Password mismatch for user %s", storedUser.Username)
		utils.RespondError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	accessJWTKey := os.Getenv("ACCESS_JWT_ACCESS_TOKEN_SECRET")

	tokenStringForAccess, err := utils.CreateToken(storedUser.UUID.String(), 3, []byte(accessJWTKey))
	if err != nil {
		log.Printf("Error creating token during register: %v", err)
		utils.RespondInternal(w, err, "Could not create session")
		return
	}

	refreshJWTKey := os.Getenv("ACCESS_JWT_REFRESH_TOKEN_SECRET")

	tokenStringForRefresh, err := utils.CreateToken(storedUser.UUID.String(), 10, []byte(refreshJWTKey))
	if err != nil {
		log.Printf("Error creating token during register: %v", err)
		utils.RespondInternal(w, err, "Could not create session")
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
		utils.RespondInternal(w, err, "Could not persist session")
		return
	}

	utils.RespondSuccess(w, http.StatusOK)

}

func (h *UserHandler) Logout(w http.ResponseWriter, r *http.Request) {

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

	utils.RespondSuccess(w, http.StatusOK)
}

func (h *UserHandler) GetUserInfo(w http.ResponseWriter, r *http.Request) {

	userID, ok := r.Context().Value(middleware.UserIDContextKey).(string)

	if !ok {
		log.Printf("Error: User ID not found in context")
		utils.RespondError(w, http.StatusUnauthorized, "Unauthorized")
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
			utils.RespondError(w, http.StatusNotFound, "User not found")
		} else {
			log.Printf("Database error while fetching user info for ID %s: %v", userID, err)
			utils.RespondError(w, http.StatusInternalServerError, "Internal server error")
		}
		return
	}

	utils.RespondSuccess(w, http.StatusOK, user)
}

func (h *UserHandler) GetSecretKey(w http.ResponseWriter, r *http.Request) {
	var password models.Password

	if err := json.NewDecoder(r.Body).Decode(&password); err != nil {
		fmt.Println(err)
		utils.RespondError(w, http.StatusBadRequest, "Password is required")
		return
	}

	userId, ok := r.Context().Value(middleware.UserIDContextKey).(string)
	if !ok {
		log.Printf("Error: User ID not found in context")
		utils.RespondError(w, http.StatusUnauthorized, "Invalid user!")
		return
	}

	row := h.DB.QueryRow("SELECT username, password_hash, email, secret_key FROM users WHERE uuid = $1", &userId)

	var user models.UserForSecretKey
	if err := row.Scan(&user.Username, &user.PasswordHash, &user.Email, &user.SecretKey); err != nil {
		if err == sql.ErrNoRows {
			log.Printf("User not found for ID: %s", userId)
			utils.RespondError(w, http.StatusNotFound, "Not found!")

		} else {
			log.Printf("Database error while fetching user info for ID %s: %v", userId, err)
			utils.RespondError(w, http.StatusInternalServerError, "Internal server error!")
		}
		return
	}

	if !utils.CheckPasswordHash(password.Password, user.PasswordHash) {
		utils.RespondError(w, http.StatusUnauthorized, "Invalid password")
		return
	}

	utils.RespondSuccess(w, http.StatusOK, user.SecretKey)
}

func (h *UserHandler) RefreshTokenVerify(w http.ResponseWriter, r *http.Request) {
	refreshCookie, err := r.Cookie("refresh_token")

	if err != nil {
		if err == http.ErrNoCookie {
			utils.RespondError(w, http.StatusUnauthorized, "Unauthorized: Authentication token required")
			return
		}
		utils.RespondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	tokenString := refreshCookie.Value

	refreshJWTKey := os.Getenv("ACCESS_JWT_REFRESH_TOKEN_SECRET")

	claims, err := utils.ParseToken(tokenString, []byte(refreshJWTKey))

	if err != nil {
		utils.RespondError(w, http.StatusUnauthorized, "Unauthorized: Invalid token")
		return
	}

	userID := claims.UserID

	accessJWTKey := os.Getenv("ACCESS_JWT_ACCESS_TOKEN_SECRET")

	accessToken, err := utils.CreateToken(userID, 24*time.Hour*3, []byte(accessJWTKey))
	if err != nil {
		utils.RespondError(w, http.StatusUnauthorized, "Internal Server Error")
		return
	}

	refreshToken, err := utils.CreateToken(userID, 24*time.Hour*30, []byte(refreshJWTKey))
	if err != nil {
		utils.RespondError(w, http.StatusUnauthorized, "Internal Server Error")
		return
	}

	redisCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)

	defer cancel()

	redisKey := fmt.Sprintf("refresh:%s", userID)

	err = h.RedisClient.Set(redisCtx, redisKey, refreshToken, 24*time.Hour*30).Err()

	if err != nil {
		utils.RespondError(w, http.StatusUnauthorized, "Internal Server Error")
	}

	utils.SetAuthCookie(w, accessToken, refreshToken)

	utils.RespondSuccess(w, http.StatusOK)

}

func (h *UserHandler) UpdateSecretKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SecretKey string `json:"secretKey"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		utils.RespondError(w, http.StatusBadRequest, "Secret key is required")
		return
	}

	userID, ok := r.Context().Value(middleware.UserIDContextKey).(string)
	if !ok {
		log.Printf("Error: User ID not found in context")
		utils.RespondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	row := h.DB.QueryRow("SELECT username, password_hash, email, secret_key FROM users WHERE uuid = $1", &userID)

	var user models.UserForSecretKey
	if err := row.Scan(&user.Username, &user.PasswordHash, &user.Email, &user.SecretKey); err != nil {
		if err == sql.ErrNoRows {
			log.Printf("User not found for ID: %s", userID)
			utils.RespondError(w, http.StatusNotFound, "Unauthorized")
		} else {
			log.Printf("Database error while fetching user info for ID %s: %v", userID, err)
			utils.RespondError(w, http.StatusInternalServerError, "Internal server error: Failed to retrieve user data")

		}
		return
	}

	if user.SecretKey != body.SecretKey {
		utils.RespondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	newSecretKey, err := utils.GenerateKey(32)

	if err != nil {
		utils.RespondError(w, http.StatusUnauthorized, "Internal server error")
		return
	}

	_, err = h.DB.Exec(`UPDATE users SET secret_key = $1 WHERE uuid = $2`, &newSecretKey, &userID)

	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Unable to update secret key")
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Add("Content-type", "application/json")

	err = json.NewEncoder(w).Encode(map[string]string{
		"message": "Secret key updated",
	})
	if err != nil {
		log.Println("Failed to encode JSON response:", err)
		utils.RespondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
}

func (h *UserHandler) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	err := updateUserPasswordLogic(h.DB, r)
	if err != nil {
		utils.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	utils.RespondSuccess(w, http.StatusOK, "Password updated!")
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

func (h *UserHandler) UpdateUserInfo(w http.ResponseWriter, r *http.Request) {
	var user models.UpdateUser
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		utils.RespondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if user.Email == "" || user.Username == "" {
		utils.RespondError(w, http.StatusBadRequest, "Email and username are required")
		return
	}

	userID, ok := r.Context().Value(middleware.UserIDContextKey).(string)
	if !ok {
		utils.RespondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	_, err := h.DB.Exec(
		`UPDATE users SET email = $1, username = $2 WHERE uuid = $3`,
		user.Email, user.Username, userID,
	)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Unable to update user info")
		return
	}

	utils.RespondString(w, http.StatusOK, "User info updated successfully")
}
