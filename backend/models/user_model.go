package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	UUID         uuid.UUID `db:"uuid" json:"uuid"`
	Username     string    `db:"username" json:"username"`
	Email        string    `db:"email" json:"email"`
	PasswordHash string    `db:"password_hash" json:"password"`
	PublicKey    string    `db:"public_key" json:"public_key"`
	SecretKey    string    `db:"secret_key" json:"-"` // savved as enum in db 1)free  2) standard 3) pro

	AccountType    string    `db:"account_type" json:"account_type"`
	MaxAPICalls    int       `db:"max_api_calls" json:"max_api_calls"`
	StorageUsedMB  int       `db:"storage_used_mb" json:"storage_used_mb"`
	StorageQuotaMB int       `db:"storage_quota_mb" json:"storage_quota_mb"`
	CreatedAt      time.Time `db:"created_at" json:"created_at"`
}

type SafeUser struct {
	UUID      uuid.UUID `json:"uuid"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	PublicKey string    `json:"public_key"`
}

type UserAPIUsage struct {
	UserUUID    uuid.UUID `db:"user_uuid" json:"user_uuid"`
	PeriodStart time.Time `db:"period_start" json:"period_start"`
	APICalls    int       `db:"api_calls" json:"api_calls"`
}

type LoginForm struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRes struct {
	Message string `json:"message"`
	Status  string `json:"status"`
}

type LogoutRes struct {
	Message string `json:"message"`
	Status  string `json:"status"`
}

type UserProfile struct {
	Uuid         uuid.UUID `json:"uuid"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PublicKey    string    `json:"public_key"`
	AccountType  string    `json:"account_type"`
	GetAPICalls  int       `json:"get_api_calls"`
	EditAPICalls int       `json:"edit_api_calls"`
	PostAPICalls int       `json:"post_api_calls"`
	CreatedAt    time.Time `json:"created_at"`
}

type Password struct {
	Password string `json:"password"`
}

type UserForSecretKey struct {
	Username     string `json:"username"`
	Email        string `json:"email"`
	PasswordHash string `db:"password_hash" json:"password_hash"`
	SecretKey    string `db:"secret_key" json:"secret_key"`
}

type UpdateUser struct {
	Email    string `json:"email"`
	Username string `json:"username"`
}
