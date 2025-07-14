package models

import (
	"time"

	"github.com/google/uuid"
)

type Image struct {
	ID               uuid.UUID `json:"id"`
	UserID           uuid.UUID `json:"user_id"`
	S3Key            string    `json:"s3_key"`
	OriginalFilename string    `json:"original_filename"`
	MimeType         string    `json:"mime_type"`
	FileSize         int64     `json:"file_size_bytes"`
	UploadDate       time.Time `json:"upload_date"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type UserForFileUpload struct {
	Username       string `json:"username"`
	Email          string `json:"email"`
	PublicKey      string `json:"public_key"`
	AccountType    string `json:"account_type"`
	MaxAPICall     int    `json:"max_api_calls"`
	StorageUsedMB  int    `json:"storage_used_mb"`
	StorageQuotaMB int    `json:"storage_quota_mb"`
	SecretKey      string `json:"secret_key"`
}

type UploadFile struct {
	URL              string    `json:"url"`
	OriginalFilename string    `json:"original_filename"`
	Id               uuid.UUID `json:"id"`
}

type SecretKeyUploadUser struct {
	ID           uuid.UUID `json:"id"`
	PublicKey    string    `json:"public_key"`
	SecretKey    string    `json:"secret_key"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PostAPICalls int16     `json:"post_api_calls"`
}


type SendAllToUserImagesUI struct{
	Url  []string  `json:"url"`
}