package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	UUID           uuid.UUID `db:"uuid" json:"uuid"`
	Username       string    `db:"username" json:"username"`
	Email          string    `db:"email" json:"email"`
	PasswordHash   string    `db:"password_hash" json:"password_hash"`
	PublicKey      string    `db:"public_key" json:"public_key"`
	SecretKey      string    `db:"secret_key" json:"-"`
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
