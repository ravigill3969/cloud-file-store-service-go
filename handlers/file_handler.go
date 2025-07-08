package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/s3/s3manager/s3manageriface"
	"github.com/google/uuid"
	middleware "github.com/ravigill3969/cloud-file-store/middlewares"
	"github.com/ravigill3969/cloud-file-store/models"
	"github.com/ravigill3969/cloud-file-store/utils"
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
		&user.SecretKey,
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

	key := "uploads/" + strconv.FormatInt(time.Now().UnixNano(), 10) + "_" + user.SecretKey + "_" + fileHeader.Filename

	contentType := fileHeader.Header.Get("Content-Type")

	err = validateContentType(contentType)

	if err != nil {
		http.Error(w, err.Error(), http.StatusUnsupportedMediaType)
		return
	}

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

	reqHttp.Header.Set("Content-Type", fileHeader.Header.
		Get("Content-Type"))

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

	query := `INSERT INTO images (user_id , s3_key, original_filename, mime_type, file_size_bytes, url ) VALUES ($1, $2, $3, $4, $5, $6) RETURNING url, original_filename, id`

	var fileUpload models.UploadFile

	err = fh.DB.QueryRow(query, userID, key, fileHeader.Filename, fileHeader.Header.Get("Content-Type"), fileHeader.Size, fileURL).Scan(&fileUpload.URL, &fileUpload.OriginalFilename, &fileUpload.Id)

	if err != nil {
		http.Error(w, "Unable to save data", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(fileUpload); err != nil {
		log.Printf("Error encoding user info to JSON: %v", err)
	}

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

func (fh *FileHandler) UploadAsThirdParty(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(10 << 20)

	if err != nil {
		http.Error(w, "Could not parse multipart form", http.StatusBadRequest)
		return
	}

	file, fileHeader, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "File not provided", http.StatusBadRequest)
		return
	}

	const maxSizeBytes = 5 * 1024 * 1024 

	if fileHeader.Size > maxSizeBytes {
		http.Error(w, "Image size exceeds 5MB limit", http.StatusBadRequest)
		return
	}

	defer file.Close()

	if fileHeader.Filename == "" {
		http.Error(w, "Filename missing in upload", http.StatusBadRequest)
		return
	}

	path := r.URL.Path

	parsedURL := strings.Split(path, "/")

	if len(parsedURL) != 6 && parsedURL[1] != "api" && parsedURL[4] != "secure" {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	secretKey := parsedURL[4]
	publicKey := parsedURL[6]

	// /api/file/upload/{secretKey}/secure/{publicKey}"

	row := fh.DB.QueryRow(`WITH user_data AS (
    SELECT uuid, public_key, secret_key, username, email
    FROM users
    WHERE public_key = $1
	),
	updated AS (
    UPDATE users
    SET post_api_calls = post_api_calls - 1
    WHERE public_key = $1 AND post_api_calls > 0
    RETURNING post_api_calls
	)
	SELECT u.uuid, u.public_key, u.secret_key, u.username, u.email, up.post_api_calls
	FROM user_data u
	JOIN updated up ON true;
	`, publicKey)

	var user models.SecretKeyUploadUser

	err = row.Scan(
		&user.ID,
		&user.PublicKey,
		&user.SecretKey,
		&user.Username,
		&user.Email,
		&user.PostAPICalls,
	)
	// 	ID           uuid.UUID `json:"id"`
	// PublicKey    string    `json:"public_key"`
	// SecretKey    string    `json:"secret_key"`
	// Username     string    `json:"username"`
	// Email        string    `json:"email"`
	// PostAPICalls int16     `json:"post_api_calls"`

	fmt.Println(err)

	if user.SecretKey != "" && secretKey != user.SecretKey {
		http.Error(w, "Invalid public key", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "Post req limit reached for this month", http.StatusUnauthorized)
		return
	}

	key := "uploads/" + strconv.FormatInt(time.Now().UnixNano(), 10) + "_" + user.SecretKey + "_" + fileHeader.Filename

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}

	contentType := fileHeader.Header.Get("Content-Type")

	err = validateContentType(contentType)

	if err != nil {
		http.Error(w, err.Error(), http.StatusUnsupportedMediaType)
		return
	}

	presignedURL, err := fh.CreatePresignedUploadRequest(fileHeader.Filename, contentType, key)

	if err != nil {
		http.Error(w, "Failed to generate presigned URL: "+err.Error(), http.StatusInternalServerError)
		return
	}

	reqHttp, err := http.NewRequest("PUT", *presignedURL, bytes.NewReader(fileBytes))
	if err != nil {
		http.Error(w, "Failed to create PUT request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	reqHttp.Header.Set("Content-Type", fileHeader.Header.
		Get("Content-Type"))

	client := &http.Client{}
	resp, err := client.Do(reqHttp)
	if err != nil {
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

	query := `INSERT INTO images (user_id , s3_key, original_filename, mime_type, file_size_bytes, url ) VALUES ($1, $2, $3, $4, $5, $6) RETURNING url, original_filename, id`

	var fileUpload models.UploadFile

	err = fh.DB.QueryRow(query, user.ID, key, fileHeader.Filename, fileHeader.Header.Get("Content-Type"), fileHeader.Size, fileURL).Scan(&fileUpload.URL, &fileUpload.OriginalFilename, &fileUpload.Id)

	if err != nil {
		http.Error(w, "Unable to save data", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(fileUpload); err != nil {
		log.Printf("Error encoding user info to JSON: %v", err)
	}

}

func validateContentType(contentType string) error {
	allowedTypes := []string{"image/jpeg", "image/png", "image/gif"}

	for _, t := range allowedTypes {
		if contentType == t {
			return nil
		}
	}
	return fmt.Errorf("unsupported image format: %s", contentType)
}

func (fh *FileHandler) ServeFileWithID(w http.ResponseWriter, r *http.Request) {
	parsedURL := strings.Split(r.URL.Path, "/")
	// /api/file/get/{id}/{publicKey}/secure/{secretKey}

	if len(parsedURL) < 8 {
		http.Error(w, "Invalid URL structure", http.StatusBadRequest)
		return
	}

	publicKey := parsedURL[5]
	photoID := parsedURL[4]
	secretKey := parsedURL[7]

	if publicKey == "" {
		http.Error(w, "Invalid public key", http.StatusBadRequest)
		return
	}

	if photoID == "" {
		http.Error(w, "Invalid id", http.StatusBadRequest)
		return
	}

	row, err := fh.DB.Exec(`UPDATE users SET get_api_calls = get_api_calls - 1 WHERE public_key = $1 AND secret_key = $2 AND get_api_calls > 1 `, &publicKey, &secretKey)

	if err != nil {
		log.Printf("DB update error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)

	}

	rowsAffected, err := row.RowsAffected()
	if err != nil {
		http.Error(w, "Something went wrong", http.StatusInternalServerError)
		return
	}

	if rowsAffected == 0 {
		http.Error(w, "Unable to update", http.StatusInternalServerError)
		return
	}

	row2 := fh.DB.QueryRow(`SELECT url FROM images WHERE id = $1`, photoID)

	var url string

	err = row2.Scan(
		&url,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Invalid image id", http.StatusBadRequest)
		} else {
			http.Error(w, "Image not found", http.StatusNotFound)

		}
		return
	}

	resp, err := http.Get(url)

	if err != nil || resp.StatusCode != http.StatusOK {
		http.Error(w, "Failed to fetch image", http.StatusBadGateway)
		return
	}

	defer resp.Body.Close()

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(http.StatusOK)
	io.Copy(w, resp.Body)
}

func (fh *FileHandler) GetFileEditStoreInS3ThenInPsqlWithWidthAndSize(w http.ResponseWriter, r *http.Request) {
	parsedURL := strings.Split(r.URL.Path, "/")

	// /api/file/edit/{id}/{publicKey}/secure/{secretKey}

	if len(parsedURL) < 7 {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}
	imageID := parsedURL[4]

	publicKey := parsedURL[5]
	secretKey := parsedURL[7]

	widthStr := r.URL.Query().Get("width")
	heightStr := r.URL.Query().Get("height")

	widthInt, err := strconv.Atoi(widthStr)
	heightInt, errH := strconv.Atoi(heightStr)

	if err != nil || errH != nil {
		http.Error(w, "Width and height are required and must be integers", http.StatusBadRequest)
		return
	}

	type Image struct {
		ID               uuid.UUID `json:"id"`
		UserID           uuid.UUID `json:"user_id"`
		S3Key            string    `json:"s3_key"`
		OriginalFilename string    `json:"original_filename"`
		MimeType         string    `json:"mime_type"`
		FileSize         int64     `json:"file_size_bytes"`
		UploadDate       time.Time `json:"upload_date"`
		Width            int16     `json:"width"`
		Height           int16     `json:"height"`
		URL              string    `json:"url"`
	}

	var image Image

	err = fh.DB.QueryRow(`
        SELECT 
            id, user_id, s3_key, original_filename, mime_type, file_size_bytes, upload_date, width, height, url FROM images WHERE id = $1`, imageID).Scan(
		&image.ID,
		&image.UserID,
		&image.S3Key,
		&image.OriginalFilename,
		&image.MimeType,
		&image.FileSize,
		&image.UploadDate,
		&image.Width,
		&image.Height,
		&image.URL,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Image not found", http.StatusNotFound)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	if widthInt == int(image.Width) && heightInt == int(image.Height) {
		utils.SendJSON(w, http.StatusOK, map[string]string{
			"id":  image.ID.String(),
			"url": image.URL,
		})
		return // <--- Important to stop execution here
	}

	str, err := LamdaMagicHere(image.S3Key, widthStr, heightStr)
	if err != nil {
		http.Error(w, "Image resize failed", http.StatusInternalServerError)
		return
	}

	tx, err := fh.DB.Begin()
	if err != nil {
		log.Println("Failed to start transaction:", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			err = tx.Commit()
		}
	}()

	query := `
		INSERT INTO images (
			id, user_id, s3_key, original_filename,
			mime_type, file_size_bytes, upload_date,
			url, width, height
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7,
			$8, $9, $10
		)
	`

	_, err = tx.Exec(query,
		image.ID, image.UserID, image.S3Key, image.OriginalFilename,
		image.MimeType, image.FileSize, image.UploadDate,
		str, int16(widthInt), int16(heightInt),
	)
	if err != nil {
		log.Println("Image insert failed:", err)
		http.Error(w, "Failed to insert image", http.StatusInternalServerError)
		return
	}

	// publicKey := parsedURL[5]
	// secretKey := parsedURL[7]

	res, err := tx.Exec(`
		UPDATE users 
		SET edit_api_calls = edit_api_calls - 1 
		WHERE id = $1 AND edit_api_calls > 0 AND secret_key = $2 AND public_key = $3
	`, image.UserID, secretKey, publicKey)
	if err != nil {
		log.Println("Failed to decrement edit_api_calls:", err)
		http.Error(w, "Failed to update API quota", http.StatusInternalServerError)
		return
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		log.Println("Error checking quota update:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if rowsAffected == 0 {
		http.Error(w, "Insufficient quota", http.StatusForbidden)
		return
	}

	utils.SendJSON(w, http.StatusOK, map[string]string{
		"url": str,
	})
}

func LamdaMagicHere(key, width, height string) (string, error) {
	baseURL := os.Getenv("AWS_LAMBDA")
	if baseURL == "" {
		return "", fmt.Errorf("AWS_LAMBDA env var not set")
	}

	params := url.Values{}
	params.Add("action", "edit")
	params.Add("bucketName", os.Getenv("AWS_BUCKET_NAME"))
	params.Add("bucketEdit", os.Getenv("AWS_BUCKET_EDIT_NAME"))
	params.Add("region", os.Getenv("AWS_REGION"))
	params.Add("key", key)
	params.Add("width", width)
	params.Add("height", height)

	fmt.Println(baseURL)
	fullURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())

	resp, err := http.Post(fullURL, "application/json", nil)

	fmt.Println("2")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	fmt.Println(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad response status: %s", resp.Status)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	editedURL := string(bodyBytes)

	fmt.Println(editedURL)

	return editedURL, nil
}
