package utils

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

func SetAuthCookie(w http.ResponseWriter, tokenStringForAccess string, tokenStringForRefresh string) {

	accessTokenExpirationTime := time.Now().Add(5 * 24 * time.Hour)
	refreshTokenExpirationTime := time.Now().Add(30 * 24 * time.Hour)

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    tokenStringForAccess,
		Expires:  accessTokenExpirationTime,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    tokenStringForRefresh,
		Expires:  refreshTokenExpirationTime,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func CreateToken(userID string, days time.Duration, jwtKey []byte) (string, error) {
	expirationTime := time.Now().Add(24 * days * time.Hour)

	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

func ParseToken(tokenString string, jwtKey []byte) (*Claims, error) {

	if len(jwtKey) == 0 {
		return nil, fmt.Errorf("JWT secret key not initialized")
	}

	parsedClaims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, parsedClaims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	}, jwt.WithLeeway(5*time.Second))

	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrInvalidKey):
			fmt.Println("Key is invalid")
		case errors.Is(err, jwt.ErrInvalidKeyType):
			fmt.Println("Key is of invalid type")
		case errors.Is(err, jwt.ErrHashUnavailable):
			fmt.Println("Requested hash function is unavailable")
		case errors.Is(err, jwt.ErrTokenMalformed):
			fmt.Println("Token is malformed")
		case errors.Is(err, jwt.ErrTokenUnverifiable):
			fmt.Println("Token is unverifiable")
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			fmt.Println("Token signature is invalid")
		case errors.Is(err, jwt.ErrTokenRequiredClaimMissing):
			fmt.Println("Token is missing required claim")
		case errors.Is(err, jwt.ErrTokenInvalidAudience):
			fmt.Println("Token has invalid audience")
		case errors.Is(err, jwt.ErrTokenExpired):
			fmt.Println("Token has expired")
		case errors.Is(err, jwt.ErrTokenUsedBeforeIssued):
			fmt.Println("Token used before issued")
		case errors.Is(err, jwt.ErrTokenInvalidIssuer):
			fmt.Println("Token has invalid issuer")
		case errors.Is(err, jwt.ErrTokenInvalidSubject):
			fmt.Println("Token has invalid subject")
		case errors.Is(err, jwt.ErrTokenNotValidYet):
			fmt.Println("Token is not valid yet")
		case errors.Is(err, jwt.ErrTokenInvalidId):
			fmt.Println("Token has invalid id")
		case errors.Is(err, jwt.ErrTokenInvalidClaims):
			fmt.Println("Token has invalid claims")
		case errors.Is(err, jwt.ErrInvalidType):
			fmt.Println("Invalid type for claim")
		default:
			fmt.Println("Unhandled error:", err)
		}
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	finalClaims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}

	return finalClaims, nil
}
