package utils

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

var jwtKey = []byte(os.Getenv("ACCESS_JWT_TOKEN_SECRET"))

func SetAuthCookie(w http.ResponseWriter, tokenString string) {

	expirationTime := time.Now().Add(5 * time.Minute)

	http.SetCookie(w, &http.Cookie{
		Name:     "token",              // Name of your cookie
		Value:    tokenString,          // The JWT string
		Expires:  expirationTime,       // When the cookie expires
		Path:     "/",                  // Cookie is valid for all paths in the domain
		HttpOnly: true,                 // Important: Prevents client-side JavaScript access
		Secure:   true,                 // Important: Cookie will only be sent over HTTPS
		SameSite: http.SameSiteLaxMode, // Recommended for CSRF protection (or StrictMode)

	})
}

func CreateToken(userID string) (string, error) {
	expirationTime := time.Now().Add(5 * time.Minute)

	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			// You can add other standard claims here if needed:
			// IssuedAt:  jwt.NewNumericDate(time.Now()),
			// Issuer:    "your-app-name",
			// Subject:   userID, // Typically the same as UserID
			// Audience:  []string{"web-app", "mobile-app"},

		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}
