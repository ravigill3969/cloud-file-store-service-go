package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/s3/s3manager/s3manageriface"
	middleware "github.com/ravigill3969/cloud-file-store/middlewares"
	"github.com/ravigill3969/cloud-file-store/models"
)

type FileHandler struct {
	DB         *sql.DB
	S3Uploader s3manageriface.UploaderAPI
	S3Client   s3iface.S3API
	S3Bucket   string
}

func (fh *FileHandler) UploadFile(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		fmt.Println("ParseMultipartForm error:", err)
		http.Error(w, "Could not parse multipart form", http.StatusBadRequest)
		return
	}

	file, fileHeader, err := r.FormFile("file")
	if err != nil {
		fmt.Println("FormFile error:", err)
		http.Error(w, "File not provided", http.StatusBadRequest)
		return
	}
	defer file.Close()

	if fileHeader.Filename == "" {
		fmt.Println("Empty filename")
		http.Error(w, "Filename missing in upload", http.StatusBadRequest)
		return
	}

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		fmt.Println("ReadAll error:", err)
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}

	key := "uploads/" + strconv.FormatInt(time.Now().UnixNano(), 10) + "_" + fileHeader.Filename

	presignedURL, err := fh.CreatePresignedUploadRequest(fileHeader.Filename, fileHeader.Header.Get("Content-Type"), key)
	if err != nil {
		fmt.Println("Presigned URL generation error:", err)
		http.Error(w, "Failed to generate presigned URL: "+err.Error(), http.StatusInternalServerError)
		return
	}

	reqHttp, err := http.NewRequest("PUT", *presignedURL, bytes.NewReader(fileBytes))
	if err != nil {
		fmt.Println("NewRequest error:", err)
		http.Error(w, "Failed to create PUT request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	reqHttp.Header.Set("Content-Type", fileHeader.Header.Get("Content-Type"))

	client := &http.Client{}
	resp, err := client.Do(reqHttp)
	if err != nil {
		fmt.Println("HTTP PUT request error:", err)
		http.Error(w, "Failed to upload file to S3", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		fmt.Println("S3 Response error:", resp.Status, string(bodyBytes))
		http.Error(w, "Failed to upload file to S3", http.StatusInternalServerError)
		return
	}

	fileURL := "https://" + fh.S3Bucket + ".s3.amazonaws.com/" + key

	userID, ok := r.Context().Value(middleware.UserIDContextKey).(string)

	if !ok {
		log.Printf("Error: User ID not found in context")
		http.Error(w, "Unauthorized: User ID not provided", http.StatusUnauthorized)
		return
	}

	row := fh.DB.QueryRow("SELECT username, email, public_key, secret_key ,account_type, max_api_calls, storage_used_mb, storage_quota_mb FROM users WHERE uuid = $1", &userID)

	var user models.UserForFileUpload

	err = row.Scan(
		&user.Username,
		&user.Email,
		&user.PublicKey,
		&user.AccountType,
		&user.MaxAPICall,
		&user.StorageUsedMB,
		&user.StorageQuotaMB,
		&user.SecretKey,
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
	json.NewEncoder(w).Encode(map[string]string{
		"message": "File uploaded successfully",
		"url":     fileURL,
	})
}

func (fh *FileHandler) CreatePresignedUploadRequest(fileName, contentType string, key string) (*string, error) {
	req, _ := fh.S3Client.PutObjectRequest(&s3.PutObjectInput{
		Bucket:      aws.String(fh.S3Bucket),
		Key:         aws.String(key),
		ContentType: aws.String(contentType),
	})

	urlStr, err := req.Presign(15 * time.Minute)
	if err != nil {
		return nil, err
	}

	return &urlStr, nil
}
