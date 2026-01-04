package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/aws/aws-sdk-go/service/s3/s3manager/s3manageriface"
	"github.com/google/uuid"
	middleware "github.com/ravigill3969/cloud-file-store/backend/middlewares"
	"github.com/ravigill3969/cloud-file-store/backend/models"
	"github.com/ravigill3969/cloud-file-store/backend/utils"
	"github.com/redis/go-redis/v9"
)

const (
	fileSizeLimitPerDayInMb = 10
	maxVideoUploadSizeBytes = 50 << 20
	maxAudioUploadSizeBytes = 30 << 20
	maxMediaFormMemory      = 100 << 20
)

type mediaType string

const (
	mediaTypeImage mediaType = "image"
	mediaTypeVideo mediaType = "video"
	mediaTypeAudio mediaType = "audio"
)

type mediaUploadResponse struct {
	FileName  string `json:"file_name"`
	MediaType string `json:"media_type"`
	URL       string `json:"url,omitempty"`
	CDNURL    string `json:"cdn_url,omitempty"`
	Error     string `json:"error,omitempty"`
}

type FileHandler struct {
	DB                  *sql.DB
	S3Uploader          s3manageriface.UploaderAPI
	S3Client            s3iface.S3API
	S3Bucket            string
	Redis               *redis.Client
	AWSCloudFrontDomain string
	BACKEND_URL         string
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
		utils.RespondError(w, http.StatusBadRequest, "Could not parse multipart form")
		return
	}

	file, fileHeader, err := r.FormFile("file")
	if err != nil {
		utils.RespondError(w, http.StatusBadRequest, "File not provided")
		return
	}

	const maxSizeBytes = 5 * 1024 * 1024

	if fileHeader.Size > maxSizeBytes {
		utils.RespondError(w, http.StatusBadRequest, "Image size exceeds 5MB limit")
		return
	}

	defer file.Close()

	if fileHeader.Filename == "" {
		utils.RespondError(w, http.StatusBadRequest, "Filename is required")
		return
	}

	path := r.URL.Path

	parsedURL := strings.Split(path, "/")

	if len(parsedURL) != 6 && parsedURL[1] != "api" && parsedURL[4] != "secure" {
		utils.RespondError(w, http.StatusBadRequest, "Invalid path")

		return
	}

	secretKey := parsedURL[6]
	publicKey := parsedURL[4]

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

	if user.SecretKey != "" && secretKey != user.SecretKey {
		utils.RespondError(w, http.StatusUnauthorized, "Invalid public or secret key")
		return
	}
	if err != nil {
		utils.RespondError(w, http.StatusUnauthorized, "Post req limit reached for this month")
		return
	}

	key := "uploads/" + strconv.FormatInt(time.Now().UnixNano(), 10) + "_" + user.SecretKey + "_" + fileHeader.Filename

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Error reading file")
		return
	}

	contentType := fileHeader.Header.Get("Content-Type")

	err = validateContentType(contentType)

	if err != nil {
		utils.RespondError(w, http.StatusUnsupportedMediaType, "Unsupported media")
		return
	}

	presignedURL, err := fh.CreatePresignedUploadRequest(fileHeader.Filename, contentType, key)

	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	reqHttp, err := http.NewRequest("PUT", *presignedURL, bytes.NewReader(fileBytes))
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Internal server error")

		return
	}

	reqHttp.Header.Set("Content-Type", fileHeader.Header.
		Get("Content-Type"))

	client := &http.Client{}
	resp, err := client.Do(reqHttp)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		fmt.Println("S3 Response error:", resp.Status, string(bodyBytes))
		utils.RespondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	fileURL := "https://" + fh.S3Bucket + ".s3.amazonaws.com/" + key
	// imageURL := fmt.Sprintf("%s/%s", fh.AWSCloudFrontDomain, key)

	query := `INSERT INTO images (user_id , s3_key, original_filename, mime_type, file_size_bytes, url, cdn_url ) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING url, original_filename, id`

	var fileUpload models.UploadFile

	err = fh.DB.QueryRow(query, user.ID, key, fileHeader.Filename, fileHeader.Header.Get("Content-Type"), fileHeader.Size, fileURL, "cdn_url").Scan(&fileUpload.URL, &fileUpload.OriginalFilename, &fileUpload.Id)

	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Unable to save data")
		return
	}

	host := os.Getenv("BACKEND_URL")

	// /api/file/get-file/{id}
	params := fmt.Sprintf("/api/file/get-file/%s", fileUpload.Id)

	url := host + params

	utils.RespondThirdParty(w, http.StatusOK, map[string]string{
		"url": url,
	})

}

func validateContentType(contentType string) error {
	allowedTypes := []string{
		// Common web formats
		"image/jpeg",
		"image/png",
		"image/gif",
		"image/webp",

		// Vector formats
		"image/svg+xml",

		// Legacy / less common but still used
		"image/bmp",
		"image/x-ms-bmp", // sometimes BMP is reported this way
		"image/tiff",

		// Apple / mobile formats
		"image/heic",
		"image/heif",

		// Icon formats
		"image/x-icon",             // .ico files
		"image/vnd.microsoft.icon", // alternate .ico MIME type

		// Photoshop & professional formats
		"image/vnd.adobe.photoshop", // .psd
		"image/x-photoshop",         // older MIME type
	}

	for _, t := range allowedTypes {
		if contentType == t {
			return nil
		}
	}
	return fmt.Errorf("unsupported image format: %s", contentType)
}

func validateAudioContentType(contentType string) error {
	allowedTypes := []string{
		"audio/mpeg",
		"audio/mp3",
		"audio/wav",
		"audio/x-wav",
		"audio/webm",
		"audio/ogg",
		"audio/flac",
		"audio/aac",
		"audio/mp4",
		"audio/3gpp",
		"audio/3gpp2",
		"audio/x-m4a",
	}

	for _, t := range allowedTypes {
		if contentType == t {
			return nil
		}
	}
	return fmt.Errorf("unsupported audio format: %s", contentType)
}

func classifyMedia(contentType string) (mediaType, error) {
	switch {
	case strings.HasPrefix(contentType, "image/"):
		return mediaTypeImage, validateContentType(contentType)
	case strings.HasPrefix(contentType, "video/"):
		return mediaTypeVideo, validateVideoContentType(contentType)
	case strings.HasPrefix(contentType, "audio/"):
		return mediaTypeAudio, validateAudioContentType(contentType)
	default:
		return "", fmt.Errorf("unsupported content type: %s", contentType)
	}
}

func (fh *FileHandler) HandleImageResizeRequestForThirdParty(w http.ResponseWriter, r *http.Request) {
	parsedURL := strings.Split(r.URL.Path, "/")

	if len(parsedURL) < 7 {
		utils.RespondError(w, http.StatusBadRequest, "Invalid URL")
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
		utils.RespondError(w, http.StatusBadRequest, "Width and height are required and must be integers")
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
            id, user_id, s3_key, original_filename, mime_type, file_size_bytes, upload_date, width, height, url FROM images WHERE id = $1 AND deleted = FALSE`, imageID).Scan(
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
			utils.RespondError(w, http.StatusNotFound, "Image not found")
		} else {
			utils.RespondError(w, http.StatusInternalServerError, "Internal server error")
		}
		return
	}

	if widthInt == int(image.Width) && heightInt == int(image.Height) {
		utils.RespondSuccess(w, http.StatusOK, map[string]string{
			"id":  image.ID.String(),
			"url": image.URL,
		})
		return
	}

	str, key, err := LamdaMagicHere(image.S3Key, widthStr, heightStr)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Image resize failed")
		return
	}

	tx, err := fh.DB.Begin()
	if err != nil {
		log.Println("Failed to start transaction:", err)
		utils.RespondError(w, http.StatusInternalServerError, "Server error")
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
			user_id, s3_key, original_filename,
			mime_type, file_size_bytes, upload_date,
			url, width, height
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7,
			$8, $9
		) RETURNING id
	`

	var imageIDEdit uuid.UUID
	err = tx.QueryRow(query,
		image.UserID, key, image.OriginalFilename,
		image.MimeType, image.FileSize, image.UploadDate,
		str, int16(widthInt), int16(heightInt),
	).Scan(&imageIDEdit)

	if err != nil {
		log.Println("Image insert failed:", err)
		utils.RespondError(w, http.StatusInternalServerError, "Failed to insert image")
		return
	}

	// You now have access to the inserted image ID
	log.Println("Inserted image ID:", imageIDEdit)

	// publicKey := parsedURL[5]
	// secretKey := parsedURL[7]

	res, err := tx.Exec(`
    UPDATE users
    SET edit_api_calls = edit_api_calls - 1
    WHERE uuid = $1 AND edit_api_calls > 0 AND secret_key = $2 AND public_key = $3
`, image.UserID, secretKey, publicKey)
	if err != nil {
		log.Println("Failed to decrement edit_api_calls:", err)
		utils.RespondError(w, http.StatusInternalServerError, "Failed to update, API quota limit reached")
		return
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		log.Println("Error checking quota update:", err)
		utils.RespondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	if rowsAffected == 0 {
		utils.RespondError(w, http.StatusForbidden, "Insufficient quota")
		return
	}

	url := os.Getenv("BACKEND_URL")
	imageURL := fmt.Sprintf("%s/api/file/get-file/%s", url, imageID)

	utils.RespondThirdParty(w, http.StatusOK, map[string]string{
		"url": imageURL,
	})
}

func LamdaMagicHere(key, width, height string) (string, string, error) {
	baseURL := os.Getenv("AWS_LAMBDA")
	if baseURL == "" {
		return "", "", fmt.Errorf("AWS_LAMBDA env var not set")
	}

	params := url.Values{}
	params.Add("action", "edit")
	params.Add("bucketName", os.Getenv("AWS_BUCKET_NAME"))
	params.Add("bucketEdit", os.Getenv("AWS_BUCKET_EDIT_NAME"))
	params.Add("region", os.Getenv("AWS_REGION"))
	params.Add("key", key)
	params.Add("width", width)
	params.Add("height", height)

	fullURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())

	resp, err := http.Post(fullURL, "application/json", nil)

	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("bad response status: %s", resp.Status)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	var result struct {
		Message string `json:"message"`
		URL     string `json:"image_url"`
		Key     string `json:"key"`
	}

	err = json.Unmarshal(bodyBytes, &result)
	if err != nil {
		return "", "", err
	}

	return result.URL, result.Key, nil
}

func (fh *FileHandler) GetAllUserFiles(w http.ResponseWriter, r *http.Request) {
	userId, ok := r.Context().Value(middleware.UserIDContextKey).(string)

	if !ok {
		utils.RespondError(w, http.StatusUnauthorized, "Unauthorized!")
		return
	}
	if userId == "" {
		utils.RespondError(w, http.StatusUnauthorized, "Unauthorized!")
		return
	}

	rows, err := fh.DB.Query(`SELECT id, original_filename, mime_type, upload_date, width, height FROM images WHERE user_id = $1 AND deleted = FALSE`, userId)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Query failed!")
		return
	}
	defer rows.Close()

	var img []models.SendAllToUserImagesUI

	for rows.Next() {
		var image models.SendAllToUserImagesUI
		err := rows.Scan(
			&image.Id,
			&image.OriginalFilename,
			&image.MimeType,
			&image.UploadDate,
			&image.Width,
			&image.Height,
		)
		if err != nil {
			fmt.Println(err)
			utils.RespondError(w, http.StatusInternalServerError, "Scan failed!")
			return
		}

		img = append(img, image)
	}

	if err = rows.Err(); err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Error reading rows!")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]any{
		"status": "success",
		"data":   img,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode response: %v", err)
		utils.RespondError(w, http.StatusInternalServerError, "Failed to send response")
	}

}

func (fh *FileHandler) enforceDailyImageLimit(ctx context.Context, userID string, fileSizeBytes int64) error {
	sizeMB := float64(fileSizeBytes) / (1024 * 1024)
	key := userID + "file-size-limit"

	current, err := fh.Redis.Get(ctx, key).Float64()
	if err != nil && err != redis.Nil {
		return fmt.Errorf("failed to check daily limit: %w", err)
	}

	if current+sizeMB > fileSizeLimitPerDayInMb {
		return fmt.Errorf("daily upload limit reached (%.1f/%.0f MB)", current, float64(fileSizeLimitPerDayInMb))
	}

	if err := fh.Redis.Set(ctx, key, current+sizeMB, 24*time.Hour).Err(); err != nil {
		return fmt.Errorf("failed to update daily limit: %w", err)
	}

	return nil
}

func (fh *FileHandler) uploadImageToS3(ctx context.Context, userID string, fileHeader *multipart.FileHeader) (models.UploadGoRoutines, error) {
	var upload models.UploadGoRoutines

	if fileHeader == nil {
		return upload, errors.New("file header is required")
	}

	if fileHeader.Filename == "" {
		return upload, errors.New("filename is required")
	}

	if err := fh.enforceDailyImageLimit(ctx, userID, fileHeader.Size); err != nil {
		return upload, err
	}

	if err := validateContentType(fileHeader.Header.Get("Content-Type")); err != nil {
		return upload, err
	}

	file, err := fileHeader.Open()
	if err != nil {
		return upload, fmt.Errorf("unable to open file: %w", err)
	}
	defer file.Close()

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		return upload, fmt.Errorf("unable to read file: %w", err)
	}

	key := fmt.Sprintf("uploads/%d_%s_%s", time.Now().UnixNano(), userID, fileHeader.Filename)

	presignedURL, err := fh.CreatePresignedUploadRequest(fileHeader.Filename, fileHeader.Header.Get("Content-Type"), key)
	if err != nil {
		return upload, fmt.Errorf("failed to generate presigned URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", *presignedURL, bytes.NewReader(fileBytes))
	if err != nil {
		return upload, fmt.Errorf("failed to create upload request: %w", err)
	}

	req.Header.Set("Content-Type", fileHeader.Header.Get("Content-Type"))

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return upload, fmt.Errorf("failed to upload to storage: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return upload, fmt.Errorf("storage upload failed with status %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	upload.Url = fmt.Sprintf("https://%s.s3.amazonaws.com/%s", fh.S3Bucket, key)
	upload.OriginalFilename = fileHeader.Filename
	upload.MimeType = fileHeader.Header.Get("Content-Type")
	upload.S3Key = key
	upload.FileSize = fileHeader.Size
	upload.CDNurl = fmt.Sprintf("%s/%s", fh.AWSCloudFrontDomain, key)
	upload.Key = key

	return upload, nil
}

func (fh *FileHandler) uploadVideoToS3(ctx context.Context, userID string, fileHeader *multipart.FileHeader) (string, error) {
	if fileHeader == nil {
		return "", errors.New("file header is required")
	}

	if fileHeader.Filename == "" {
		return "", errors.New("filename is required")
	}

	if fileHeader.Size > maxVideoUploadSizeBytes {
		return "", fmt.Errorf("file size limit is %dMB", maxVideoUploadSizeBytes/(1<<20))
	}

	if err := validateVideoContentType(fileHeader.Header.Get("Content-Type")); err != nil {
		return "", err
	}

	file, err := fileHeader.Open()
	if err != nil {
		return "", fmt.Errorf("failed to open uploaded file: %w", err)
	}
	defer file.Close()

	key := fmt.Sprintf("media/video/%s/%d_%s", userID, time.Now().UnixNano(), fileHeader.Filename)

	_, err = fh.S3Uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(fh.S3Bucket),
		Key:    aws.String(key),
		Body:   file,
	})
	if err != nil {
		return "", fmt.Errorf("failed to upload to S3: %w", err)
	}

	url := fmt.Sprintf("https://%s.s3.amazonaws.com/%s", fh.S3Bucket, key)
	id, err := fh.saveMediaToDB(userID, key, fileHeader.Filename, fileHeader.Header.Get("Content-Type"), fileHeader.Size, url)
	if err != nil {
		return "", fmt.Errorf("failed to persist media metadata: %w", err)
	}

	return fh.buildMediaStreamURL(id), nil
}

func (fh *FileHandler) uploadAudioToS3(ctx context.Context, userID string, fileHeader *multipart.FileHeader) (string, error) {
	if fileHeader == nil {
		return "", errors.New("file header is required")
	}

	if fileHeader.Filename == "" {
		return "", errors.New("filename is required")
	}

	if fileHeader.Size > maxAudioUploadSizeBytes {
		return "", fmt.Errorf("file size limit is %dMB", maxAudioUploadSizeBytes/(1<<20))
	}

	if err := validateAudioContentType(fileHeader.Header.Get("Content-Type")); err != nil {
		return "", err
	}

	file, err := fileHeader.Open()
	if err != nil {
		return "", fmt.Errorf("failed to open uploaded file: %w", err)
	}
	defer file.Close()

	key := fmt.Sprintf("media/audio/%s/%d_%s", userID, time.Now().UnixNano(), fileHeader.Filename)

	_, err = fh.S3Uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(fh.S3Bucket),
		Key:    aws.String(key),
		Body:   file,
	})
	if err != nil {
		return "", fmt.Errorf("failed to upload to S3: %w", err)
	}

	url := fmt.Sprintf("https://%s.s3.amazonaws.com/%s", fh.S3Bucket, key)
	id, err := fh.saveMediaToDB(userID, key, fileHeader.Filename, fileHeader.Header.Get("Content-Type"), fileHeader.Size, url)
	if err != nil {
		return "", fmt.Errorf("failed to persist media metadata: %w", err)
	}

	return fh.buildMediaStreamURL(id), nil
}

func (fh *FileHandler) buildMediaStreamURL(id uuid.UUID) string {
	baseURL := os.Getenv("BACKEND_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	return fmt.Sprintf("%s/api/video/watch?vid=%s", baseURL, id.String())
}

func (fh *FileHandler) UploadMedia(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(maxMediaFormMemory); err != nil {
		utils.RespondError(w, http.StatusBadRequest, "Could not parse multipart form")
		return
	}

	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		utils.RespondError(w, http.StatusBadRequest, "No file provided. Use form field 'file'")
		return
	}

	userID, ok := r.Context().Value(middleware.UserIDContextKey).(string)
	if !ok || userID == "" {
		utils.RespondError(w, http.StatusUnauthorized, "Unauthorized: user id missing")
		return
	}

	var uploaded []mediaUploadResponse
	var failed []mediaUploadResponse
	var pendingImages []models.UploadGoRoutines
	var pendingImageResults []mediaUploadResponse

	for _, fileHeader := range files {
		result := mediaUploadResponse{
			FileName: fileHeader.Filename,
		}

		mediaKind, err := classifyMedia(fileHeader.Header.Get("Content-Type"))
		if err != nil {
			result.Error = err.Error()
			failed = append(failed, result)
			continue
		}
		result.MediaType = string(mediaKind)

		switch mediaKind {
		case mediaTypeImage:
			upload, err := fh.uploadImageToS3(r.Context(), userID, fileHeader)
			if err != nil {
				result.Error = err.Error()
				failed = append(failed, result)
				continue
			}
			pendingImages = append(pendingImages, upload)
			result.URL = upload.Url
			result.CDNURL = upload.CDNurl
			pendingImageResults = append(pendingImageResults, result)
		case mediaTypeVideo:
			url, err := fh.uploadVideoToS3(r.Context(), userID, fileHeader)
			if err != nil {
				result.Error = err.Error()
				failed = append(failed, result)
				continue
			}
			result.URL = url
			uploaded = append(uploaded, result)
		case mediaTypeAudio:
			url, err := fh.uploadAudioToS3(r.Context(), userID, fileHeader)
			if err != nil {
				result.Error = err.Error()
				failed = append(failed, result)
				continue
			}
			result.URL = url
			uploaded = append(uploaded, result)
		default:
			result.Error = "unsupported media type"
			failed = append(failed, result)
		}
	}

	if len(pendingImages) > 0 {
		if err := fh.SaveUploadedImages(pendingImages, userID); err != nil {
			for _, res := range pendingImageResults {
				res.Error = fmt.Sprintf("uploaded to storage but failed to save metadata: %v", err)
				res.URL = ""
				res.CDNURL = ""
				failed = append(failed, res)
			}
		} else {
			uploaded = append(uploaded, pendingImageResults...)
		}
	}

	status := http.StatusOK
	if len(uploaded) == 0 {
		status = http.StatusBadRequest
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"uploaded": uploaded,
		"failed":   failed,
	}); err != nil {
		log.Printf("Failed to encode upload response: %v", err)
	}
}

func (fh *FileHandler) UploadFilesWithGoRoutines(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(maxMediaFormMemory); err != nil {
		utils.RespondError(w, http.StatusBadRequest, "Could not parse multipart form")
		return
	}

	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		utils.RespondError(w, http.StatusBadRequest, "No files uploaded. Use form field 'file'.")
		return
	}

	userID, ok := r.Context().Value(middleware.UserIDContextKey).(string)
	if !ok || userID == "" {
		utils.RespondError(w, http.StatusUnauthorized, "Unauthorized: User ID not provided")
		return
	}

	var uploaded []mediaUploadResponse
	var failed []mediaUploadResponse
	var pendingImages []models.UploadGoRoutines
	var pendingImageResults []mediaUploadResponse

	for _, fileHeader := range files {
		result := mediaUploadResponse{
			FileName: fileHeader.Filename,
		}

		mediaKind, err := classifyMedia(fileHeader.Header.Get("Content-Type"))
		if err != nil {
			result.Error = err.Error()
			failed = append(failed, result)
			continue
		}

		result.MediaType = string(mediaKind)

		switch mediaKind {
		case mediaTypeImage:
			upload, err := fh.uploadImageToS3(r.Context(), userID, fileHeader)
			if err != nil {
				result.Error = err.Error()
				failed = append(failed, result)
				continue
			}
			pendingImages = append(pendingImages, upload)
			result.URL = upload.Url
			result.CDNURL = upload.CDNurl
			pendingImageResults = append(pendingImageResults, result)
		case mediaTypeVideo:
			url, err := fh.uploadVideoToS3(r.Context(), userID, fileHeader)
			if err != nil {
				result.Error = err.Error()
				failed = append(failed, result)
				continue
			}
			result.URL = url
			uploaded = append(uploaded, result)
		case mediaTypeAudio:
			url, err := fh.uploadAudioToS3(r.Context(), userID, fileHeader)
			if err != nil {
				result.Error = err.Error()
				failed = append(failed, result)
				continue
			}
			result.URL = url
			uploaded = append(uploaded, result)
		default:
			result.Error = "unsupported media type"
			failed = append(failed, result)
		}
	}

	if len(pendingImages) > 0 {
		if err := fh.SaveUploadedImages(pendingImages, userID); err != nil {
			for _, res := range pendingImageResults {
				res.Error = fmt.Sprintf("uploaded to storage but failed to save metadata: %v", err)
				res.URL = ""
				res.CDNURL = ""
				failed = append(failed, res)
			}
		} else {
			uploaded = append(uploaded, pendingImageResults...)
		}
	}

	status := http.StatusOK
	if len(uploaded) == 0 {
		status = http.StatusBadRequest
	} else if len(failed) > 0 {
		status = http.StatusPartialContent
	}

	utils.RespondSuccess(w, status, map[string]any{
		"uploaded": uploaded,
		"failed":   failed,
	})
}

func (fh *FileHandler) SaveUploadedImages(images []models.UploadGoRoutines, userID string) error {
	if len(images) == 0 {
		return nil
	}

	tx, err := fh.DB.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	stmt, err := tx.Prepare(`
		INSERT INTO images (user_id, url, original_filename, mime_type, width, height, s3_key,file_size_bytes, cdn_url)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, img := range images {
		_, err = stmt.Exec(userID, img.Url, img.OriginalFilename, img.MimeType, img.Width, img.Height, img.S3Key, img.FileSize, img.CDNurl)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (fh *FileHandler) ServeFileWithIDForUI(w http.ResponseWriter, r *http.Request) {
	parsedURL := strings.Split(r.URL.Path, "/")

	if len(parsedURL) < 4 {
		utils.RespondError(w, http.StatusBadRequest, "Invalid URL structure")
		return
	}

	photoID := parsedURL[4]

	if photoID == "" {
		utils.RespondError(w, http.StatusBadRequest, "Invalid id")
		return
	}

	row2 := fh.DB.QueryRow(`SELECT url FROM images WHERE id = $1`, photoID)

	var url string

	err := row2.Scan(
		&url,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			utils.RespondError(w, http.StatusBadRequest, "Invalid image id")
		} else {
			utils.RespondError(w, http.StatusNotFound, "Image not found")

		}
		return
	}

	resp, err := http.Get(url)

	if err != nil || resp.StatusCode != http.StatusOK {
		utils.RespondError(w, http.StatusBadGateway, "Failed to fetch image")
		return
	}

	defer resp.Body.Close()

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(http.StatusOK)
	io.Copy(w, resp.Body)
}

func (fh *FileHandler) ServeFileWithIDForThirdParty(w http.ResponseWriter, r *http.Request) {
	parsedURL := strings.Split(r.URL.Path, "/")
	if len(parsedURL) < 5 {
		utils.RespondError(w, http.StatusBadRequest, "Invalid URL structure")
		return
	}

	photoID := parsedURL[4]
	if photoID == "" {
		utils.RespondError(w, http.StatusBadRequest, "Invalid id")
		return
	}

	if fh.serveFromCache(w, photoID) {
		return
	}

	fh.serveFromSource(w, r, photoID)
}

func (fh *FileHandler) serveFromCache(w http.ResponseWriter, photoID string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	key := fmt.Sprintf("image:%s", photoID)
	rawData, err := fh.Redis.Get(ctx, key).Bytes()
	if err != nil {
		return false
	}

	var payload map[string]string
	if err := json.Unmarshal(rawData, &payload); err != nil {
		log.Printf("Error unmarshaling cached data for %s: %v", photoID, err)
		return false
	}

	imageBytes, err := base64.StdEncoding.DecodeString(payload["image"])
	if err != nil {
		log.Printf("Error decoding base64 for %s: %v", photoID, err)
		return false
	}

	w.Header().Set("Content-Type", payload["content-type"])
	w.Header().Set("Cache-Control", "public, max-age=600")

	if _, err := w.Write(imageBytes); err != nil {
		log.Printf("Error writing cached image to response: %v", err)
		return false
	}

	return true
}

func (fh *FileHandler) serveFromSource(w http.ResponseWriter, r *http.Request, photoID string) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	row := fh.DB.QueryRowContext(ctx, `SELECT url FROM images WHERE id = $1`, photoID)
	var url string
	err := row.Scan(&url)
	if err != nil {
		if err == sql.ErrNoRows {
			utils.RespondError(w, http.StatusNotFound, "Image not found")
		} else {
			log.Printf("Database error for image %s: %v", photoID, err)
			utils.RespondError(w, http.StatusInternalServerError, "Internal server error")
		}
		return
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		log.Printf("Error fetching image from %s: %v", url, err)
		utils.RespondError(w, http.StatusBadGateway, "Failed to fetch image")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Non-200 status code %d when fetching %s", resp.StatusCode, url)
		utils.RespondError(w, http.StatusBadGateway, "Failed to fetch image")
		return
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=600")

	var cacheBuffer bytes.Buffer
	multiWriter := io.MultiWriter(w, &cacheBuffer)

	if _, err := io.Copy(multiWriter, resp.Body); err != nil {
		log.Printf("Error serving/collecting image %s: %v", photoID, err)
		return
	}

	go func() {
		if err := fh.cacheImageInRedis(photoID, contentType, cacheBuffer.Bytes()); err != nil {
			log.Printf("Error caching image %s: %v", photoID, err)
		}
	}()
}

func (fh *FileHandler) cacheImageInRedis(photoID, contentType string, data []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const maxCacheSize = 10 * 1024 * 1024
	if len(data) > maxCacheSize {
		log.Printf("Skipping cache for image %s: too large (%d bytes)", photoID, len(data))
		return nil
	}

	key := "image:" + photoID
	encoded := base64.StdEncoding.EncodeToString(data)

	payload := map[string]string{
		"image":        encoded,
		"content-type": contentType,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal cache payload: %w", err)
	}

	// Cache for 10 minutes
	if err := fh.Redis.Set(ctx, key, jsonData, 10*time.Minute).Err(); err != nil {
		return fmt.Errorf("failed to set cache: %w", err)
	}

	return nil
}

func (fh *FileHandler) DownloadFile(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("iid")

	if id == "" {
		utils.RespondError(w, http.StatusBadRequest, "Missing 'key' parameter")
		return
	}

	var s3key string

	err := fh.DB.QueryRow(`SELECT s3_key FROM images WHERE id = $1 AND deleted = FALSE`, id).Scan(&s3key)

	if err != nil {
		utils.RespondError(w, http.StatusNotFound, "Not found!")
		return
	}

	output, err := fh.S3Client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(fh.S3Bucket),
		Key:    aws.String(s3key),
	})
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Failed to get object from S3: "+err.Error())
		return
	}
	defer output.Body.Close()

	filename := path.Base(s3key)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Type", aws.StringValue(output.ContentType))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", *output.ContentLength))

	_, err = io.Copy(w, output.Body)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Failed to stream file")
		return
	}
}

func removeImageFromRedis(photoID string, redisClient *redis.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	key := fmt.Sprintf("image:%s", photoID)
	err := redisClient.Del(ctx, key).Err()
	if err != nil {
		fmt.Printf("Failed to delete key %s from Redis: %v\n", key, err)
	}
	return err
}

//delete images functionality from here

func (fh *FileHandler) DeleteImages(w http.ResponseWriter, r *http.Request) {
	imageID := r.URL.Query().Get("iid") //iid := image id
	// s3Key := r.URL.Query().Get("s3_key")   //from ii, one i is for image

	fmt.Println(imageID)

	userID := r.Context().Value(middleware.UserIDContextKey)

	res, err := fh.DB.Exec(
		`UPDATE images SET deleted = TRUE, deleted_at = now() WHERE id = $1 AND user_id = $2 AND deleted = false`,
		imageID, userID,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			utils.RespondError(w, http.StatusNotFound, "Not found")
		} else {
			utils.RespondError(w, http.StatusInternalServerError, "Internal server error")
		}
		return
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Could not determine deletion result")
		return
	}

	if rowsAffected == 0 {
		utils.RespondError(w, http.StatusNotFound, "No image deleted (maybe wrong ID or unauthorized)")
		return
	}

	utils.RespondSuccess(w, http.StatusOK, "Image deleted successfully")

	go removeImageFromRedis(imageID, fh.Redis)
}

func (fh *FileHandler) ListSoftDeletedImagesByUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.UserIDContextKey).(string)

	if !ok {
		utils.RespondError(w, http.StatusUnauthorized, "Please login to perform this action.")
		return
	}

	if userID == "" {
		utils.RespondError(w, http.StatusUnauthorized, "Please login to perform this action.")
		return
	}

	rows, err := fh.DB.Query(`SELECT id FROM images WHERE deleted = true AND user_id = $1`, userID)
	var images []string

	defer rows.Close()

	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	for rows.Next() {
		var id string

		if err := rows.Scan(&id); err != nil {
			utils.RespondError(w, http.StatusInternalServerError, "Internal server error")
			return
		}

		images = append(images, id)
	}

	res := map[string]any{
		"status": "success",
		"data":   images,
	}
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(&res); err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Unable to encode to json.")
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (fh *FileHandler) RecoverDeletedImage(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.UserIDContextKey).(string)

	if !ok {
		utils.RespondError(w, http.StatusUnauthorized, "Please login to perform this action.")
		return
	}

	if userID == "" {
		utils.RespondError(w, http.StatusUnauthorized, "Please login to perform this action.")
		return
	}

	id := r.URL.Query().Get("id")

	if id == "" {
		utils.RespondError(w, http.StatusBadRequest, "id is required")
		return
	}

	result, err := fh.DB.Exec(`UPDATE images SET deleted = false, deleted_at = NULL WHERE id = $1 AND user_id = $2`, id, userID)

	fmt.Println(err)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	rowsAffected, err := result.RowsAffected()

	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	if rowsAffected == 0 {
		utils.RespondError(w, http.StatusUnauthorized, "No image found")
		return
	}

	utils.RespondSuccess(w, http.StatusOK)

}

func (fh *FileHandler) HandleImageResizeRequestForUser(w http.ResponseWriter, r *http.Request) {
	parsedURL := strings.Split(r.URL.Path, "/")

	if len(parsedURL) < 4 {
		utils.RespondError(w, http.StatusBadRequest, "Invalid URL")
		return
	}

	userID := r.Context().Value(middleware.UserIDContextKey)

	fmt.Println(userID)

	imageID := parsedURL[4]
	widthStr := r.URL.Query().Get("width")
	heightStr := r.URL.Query().Get("height")

	widthInt, err := strconv.Atoi(widthStr)
	heightInt, errH := strconv.Atoi(heightStr)

	if err != nil || errH != nil {
		utils.RespondError(w, http.StatusBadRequest, "Width and height are required and must be integers")
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
            id, user_id, s3_key, original_filename, mime_type, file_size_bytes, upload_date, width, height, url FROM images WHERE id = $1 AND deleted = FALSE`, imageID).Scan(
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
		fmt.Println(err)
		if err == sql.ErrNoRows {
			utils.RespondError(w, http.StatusNotFound, "Image not found")
		} else {
			utils.RespondError(w, http.StatusInternalServerError, "Internal server error")
		}
		return
	}

	if widthInt == int(image.Width) && heightInt == int(image.Height) {
		utils.RespondSuccess(w, http.StatusOK, map[string]string{
			"id":  image.ID.String(),
			"url": image.URL,
		})
		return
	}

	str, key, err := LamdaMagicHere(image.S3Key, widthStr, heightStr)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Image resize failed")
		return
	}

	tx, err := fh.DB.Begin()
	if err != nil {
		log.Println("Failed to start transaction:", err)
		utils.RespondError(w, http.StatusInternalServerError, "Server error")
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
			user_id, s3_key, original_filename,
			mime_type, file_size_bytes, upload_date,
			url, width, height
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7,
			$8, $9
		) RETURNING id
	`

	var imageIDEdit uuid.UUID
	err = tx.QueryRow(query,
		image.UserID, key, image.OriginalFilename,
		image.MimeType, image.FileSize, image.UploadDate,
		str, int16(widthInt), int16(heightInt),
	).Scan(&imageIDEdit)

	if err != nil {
		log.Println("Image insert failed:", err)
		utils.RespondError(w, http.StatusInternalServerError, "Failed to insert image")
		return
	}

	// You now have access to the inserted image ID
	log.Println("Inserted image ID:", imageIDEdit)

	// publicKey := parsedURL[5]
	// secretKey := parsedURL[7]

	res, err := tx.Exec(`
    UPDATE users
    SET edit_api_calls = edit_api_calls - 1
    WHERE uuid = $1 
`, userID)
	if err != nil {
		log.Println("Failed to decrement edit_api_calls:", err)
		utils.RespondError(w, http.StatusInternalServerError, "Failed to update, API quota limit reached")
		return
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		log.Println("Error checking quota update:", err)
		utils.RespondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	if rowsAffected == 0 {
		utils.RespondError(w, http.StatusForbidden, "Insufficient quota")
		return
	}

	url := os.Getenv("BACKEND_URL")
	imageURL := fmt.Sprintf("%s/api/file/get-file/%s", url, imageID)

	utils.RespondThirdParty(w, http.StatusOK, map[string]string{
		"url": imageURL,
	})
}

func (fh *FileHandler) HardDeleteSoftDeletedImage(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.UserIDContextKey).(string)

	if !ok {
		utils.RespondError(w, http.StatusUnauthorized, "Please login to perform this action.")
		return
	}

	if userID == "" {
		utils.RespondError(w, http.StatusUnauthorized, "Please login to perform this action.")
		return
	}

	id := r.URL.Query().Get("id")

	if id == "" {
		utils.RespondError(w, http.StatusBadRequest, "id is required")
		return
	}

	var key string

	err := fh.DB.QueryRow(
		`SELECT s3_key FROM images WHERE id = $1 AND user_id = $2`,
		id, userID,
	).Scan(&key)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			utils.RespondError(w, http.StatusNotFound, "Image not found")
		} else {
			utils.RespondError(w, http.StatusInternalServerError, "Internal server error")
		}
		return
	}

	bucket := os.Getenv("AWS_BUCKET_NAME")
	if bucket == "" {
		log.Println("AWS_BUCKET_NAME environment variable is not set")
		utils.RespondError(w, http.StatusInternalServerError, "Missing bucket name")
		return
	}

	_, err = fh.S3Client.DeleteObject(&s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})

	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Failed to delete from S3")
		return
	}

	result, err := fh.DB.Exec(`DELETE FROM images WHERE id = $1 AND user_id = $2`, id, userID)

	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	rowsAffected, err := result.RowsAffected()

	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	if rowsAffected == 0 {
		utils.RespondError(w, http.StatusUnauthorized, "No image found")
		return
	}

	utils.RespondSuccess(w, http.StatusOK)

	go removeImageFromRedis(id, fh.Redis)

}

func (fh *FileHandler) DeleteImageForThirdParty(w http.ResponseWriter, r *http.Request) {
	parsedURL := strings.Split(r.URL.Path, "/")

	if len(parsedURL) < 7 {
		utils.RespondError(w, http.StatusBadRequest, "Invalid URL")
		return
	}
	imageID := parsedURL[4]

	publicKey := parsedURL[5]
	secretKey := parsedURL[7]

	user_id, err := fh.GetUserIdFromSecretKeyAndPublicKey(publicKey, secretKey)

	if err != nil {
		utils.RespondError(w, http.StatusUnauthorized, "You are  unauthorized to delete this image!")
		return
	}

	res, err := fh.DB.Exec(
		`UPDATE images SET deleted = TRUE, deleted_at = now() WHERE id = $1 AND deleted = false AND user_id = $2 `,
		imageID, user_id,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			utils.RespondError(w, http.StatusNotFound, "Not found")
		} else {
			utils.RespondError(w, http.StatusInternalServerError, "Internal server error")
		}
		return
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Could not determine deletion result")
		return
	}

	if rowsAffected == 0 {
		utils.RespondError(w, http.StatusNotFound, "No image deleted (maybe wrong ID or unauthorized)")
		return
	}

}

func (fh *FileHandler) GetUserIdFromSecretKeyAndPublicKey(pubKey, secKey string) (uuid.UUID, error) {
	var id uuid.UUID

	query := `SELECT uuid FROM users WHERE public_key = $1 AND secret_key = $2`
	err := fh.DB.QueryRow(query, pubKey, secKey).Scan(&id)

	if err != nil {
		if err == sql.ErrNoRows {
			return uuid.Nil, fmt.Errorf("no user found for given keys")
		}
		return uuid.Nil, err
	}

	if id == uuid.Nil {
		return uuid.Nil, fmt.Errorf("invalid UUID retrieved")
	}

	return id, nil
}

// Video Handling Methods

func (fh *FileHandler) VideoUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(maxMediaFormMemory); err != nil {
		utils.RespondError(w, http.StatusBadRequest, "Could not parse multipart form")
		return
	}

	userID, ok := r.Context().Value(middleware.UserIDContextKey).(string)
	if !ok || userID == "" {
		utils.RespondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	files := r.MultipartForm.File["video"]
	if len(files) == 0 {
		utils.RespondError(w, http.StatusBadRequest, "No video file provided")
		return
	}

	type uploadResult struct {
		Filename string
		URL      string
		Error    error
	}

	resChan := make(chan uploadResult, len(files))
	var wg sync.WaitGroup

	for _, fhFile := range files {
		wg.Add(1)

		go func(fhFile *multipart.FileHeader) {
			defer wg.Done()

			url, err := fh.uploadVideoToS3(r.Context(), userID, fhFile)
			if err != nil {
				resChan <- uploadResult{Filename: fhFile.Filename, Error: err}
				return
			}

			resChan <- uploadResult{Filename: fhFile.Filename, URL: url}
		}(fhFile)
	}

	wg.Wait()
	close(resChan)

	var successURL []string
	var errMsg []string

	for res := range resChan {
		if res.Error != nil {
			errMsg = append(errMsg, res.Error.Error())
		} else {
			successURL = append(successURL, res.URL)
		}
	}

	if len(errMsg) > 0 {
		if len(successURL) == 0 {
			utils.RespondError(w, http.StatusBadRequest, fmt.Sprintf("Errors: %v", errMsg))
			return
		}

		w.Header().Set("Content-type", "application/json")
		w.WriteHeader(http.StatusPartialContent)
		response := map[string]any{
			"success": successURL,
			"error":   errMsg,
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			utils.RespondError(w, http.StatusInternalServerError, "Internal server error")
		}
		return
	}

	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := map[string]any{
		"success": successURL,
		"error":   errMsg,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Internal server error")
	}
}

func (fh *FileHandler) HandleMediaStreamingRequest(w http.ResponseWriter, r *http.Request) {
	vid := r.URL.Query().Get("vid")
	if vid == "" {
		utils.RespondError(w, http.StatusBadRequest, "Invalid Id")
		return
	}

	s3Key, err := fh.getMediaS3Key(vid)
	if err != nil {
		utils.RespondError(w, http.StatusNotFound, "Video not found")
		return
	}

	rangeHeader := r.Header.Get("Range")
	input := &s3.GetObjectInput{
		Bucket: aws.String(fh.S3Bucket),
		Key:    aws.String(s3Key),
	}
	if rangeHeader != "" {
		input.Range = aws.String(rangeHeader)
	}

	resp, err := fh.S3Client.GetObject(input)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Error fetching video")
		return
	}
	defer resp.Body.Close()

	if resp.ContentLength != nil {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", *resp.ContentLength))
	}
	if resp.ContentType != nil {
		w.Header().Set("Content-Type", *resp.ContentType)
	}
	if resp.ContentRange != nil {
		w.Header().Set("Content-Range", *resp.ContentRange)
		w.WriteHeader(http.StatusPartialContent)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	w.Header().Set("Accept-Ranges", "bytes")

	_, err = io.Copy(w, resp.Body)
	if err != nil {
		return
	}
}

func (fh *FileHandler) DeleteVideoWithUserID(w http.ResponseWriter, r *http.Request) {
	vid := r.URL.Query().Get("vid")
	if vid == "" {
		utils.RespondError(w, http.StatusBadRequest, "Invalid Id")
		return
	}

	userId, ok := r.Context().Value(middleware.UserIDContextKey).(string)
	if !ok || userId == "" {
		utils.RespondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	err := fh.deleteMediaFromDB(vid, userId)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.RespondString(w, http.StatusOK, "video deleted successfully")
}

func (fh *FileHandler) UploadVideoForThirdParty(w http.ResponseWriter, r *http.Request) {
	parsedUrl := strings.Split(r.URL.Path, "/")
	if len(parsedUrl) < 7 {
		utils.RespondError(w, http.StatusBadRequest, "Invalid URL format")
		return
	}
	publicKey := parsedUrl[4]
	secretKey := parsedUrl[6]

	var userID uuid.UUID
	err := fh.DB.QueryRow(`SELECT uuid FROM users WHERE public_key = $1 AND secret_key = $2`, publicKey, secretKey).Scan(&userID)
	if err != nil {
		utils.RespondError(w, http.StatusUnauthorized, "Invalid keys")
		return
	}

	if err := r.ParseMultipartForm(50 << 20); err != nil {
		utils.RespondError(w, http.StatusBadRequest, "Could not parse multipart form")
		return
	}

	files := r.MultipartForm.File["video"]
	if len(files) == 0 {
		utils.RespondError(w, http.StatusBadRequest, "No video file provided")
		return
	}

	fileHeader := files[0]

	streamURL, err := fh.uploadVideoToS3(r.Context(), userID.String(), fileHeader)
	if err != nil {
		utils.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := map[string]any{
		"success": streamURL,
		"error":   "",
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Failed to encode response: "+err.Error())
	}
}

func (fh *FileHandler) DeleteVideoForThirdParty(w http.ResponseWriter, r *http.Request) {
	parsedUrl := strings.Split(r.URL.Path, "/")
	if len(parsedUrl) < 8 {
		utils.RespondError(w, http.StatusBadRequest, "Invalid URL format")
		return
	}

	publicKey := parsedUrl[4]
	secretKey := parsedUrl[6]
	vid := parsedUrl[7]

	var userID uuid.UUID
	err := fh.DB.QueryRow(`SELECT uuid FROM users WHERE public_key = $1 AND secret_key = $2`, publicKey, secretKey).Scan(&userID)
	if err != nil {
		utils.RespondError(w, http.StatusUnauthorized, "Invalid keys")
		return
	}

	err = fh.deleteMediaFromDB(vid, userID.String())
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.RespondSuccess(w, http.StatusOK, "video deleted successfully")
}

// UploadMediaForThirdParty handles media uploads (image/video/audio) for third-party integrations
func (fh *FileHandler) UploadMediaForThirdParty(w http.ResponseWriter, r *http.Request) {
	parsedUrl := strings.Split(r.URL.Path, "/")
	if len(parsedUrl) < 7 {
		utils.RespondError(w, http.StatusBadRequest, "Invalid URL format")
		return
	}
	publicKey := parsedUrl[4]
	secretKey := parsedUrl[6]

	// Authenticate user and decrement API calls
	row := fh.DB.QueryRow(`WITH user_data AS (
		SELECT uuid, public_key, secret_key, username, email
		FROM users
		WHERE public_key = $1
	),
	updated AS (
		UPDATE users
		SET post_api_calls = post_api_calls - 0
		WHERE public_key = $1 AND post_api_calls = 0
		RETURNING post_api_calls
	)
	SELECT u.uuid, u.public_key, u.secret_key, u.username, u.email, up.post_api_calls
	FROM user_data u
	JOIN updated up ON true;
	`, publicKey)

	var user models.SecretKeyUploadUser
	err := row.Scan(
		&user.ID,
		&user.PublicKey,
		&user.SecretKey,
		&user.Username,
		&user.Email,
		&user.PostAPICalls,
	)

	if user.SecretKey != "" && secretKey != user.SecretKey {
		utils.RespondError(w, http.StatusUnauthorized, "Invalid public or secret key")
		return
	}
	if err != nil {
		utils.RespondError(w, http.StatusUnauthorized, "Post req limit reached for this month")
		return
	}

	// Parse multipart form
	if err := r.ParseMultipartForm(maxMediaFormMemory); err != nil {
		utils.RespondError(w, http.StatusBadRequest, "Could not parse multipart form")
		return
	}

	// Get file from form
	file, fileHeader, err := r.FormFile("file")
	if err != nil {
		utils.RespondError(w, http.StatusBadRequest, "File not provided")
		return
	}
	defer file.Close()

	if fileHeader.Filename == "" {
		utils.RespondError(w, http.StatusBadRequest, "Filename is required")
		return
	}

	contentType := fileHeader.Header.Get("Content-Type")

	// Classify media type
	mediaType, err := classifyMedia(contentType)
	if err != nil {
		utils.RespondError(w, http.StatusUnsupportedMediaType, err.Error())
		return
	}

	ctx := r.Context()
	userIDStr := user.ID.String()

	var response mediaUploadResponse
	response.FileName = fileHeader.Filename
	response.MediaType = string(mediaType)

	// Route to appropriate upload handler
	switch mediaType {
	case mediaTypeImage:
		url, err := fh.uploadImageForThirdParty(ctx, userIDStr, fileHeader)
		if err != nil {
			response.Error = err.Error()
			utils.RespondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		response.URL = url

	case mediaTypeVideo:
		url, err := fh.uploadVideoForThirdPartyMedia(ctx, userIDStr, fileHeader)
		if err != nil {
			response.Error = err.Error()
			utils.RespondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		response.URL = url

	case mediaTypeAudio:
		url, err := fh.uploadAudioForThirdParty(ctx, userIDStr, fileHeader)
		if err != nil {
			response.Error = err.Error()
			utils.RespondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		response.URL = url

	default:
		utils.RespondError(w, http.StatusUnsupportedMediaType, "Unsupported media type")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Failed to encode response")
	}
}

// uploadImageForThirdParty handles image uploads for third-party integrations
func (fh *FileHandler) uploadImageForThirdParty(ctx context.Context, userID string, fileHeader *multipart.FileHeader) (string, error) {
	const maxImageSize = 10 * 1024 * 1024 // 10MB
	if fileHeader.Size > maxImageSize {
		return "", fmt.Errorf("image size exceeds 10MB limit")
	}

	file, err := fileHeader.Open()
	if err != nil {
		return "", fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	// Generate S3 key
	key := fmt.Sprintf("uploads/%d_%s_%s", time.Now().UnixNano(), userID, fileHeader.Filename)

	// Upload to S3
	_, err = fh.S3Uploader.UploadWithContext(ctx, &s3manager.UploadInput{
		Bucket:      aws.String(fh.S3Bucket),
		Key:         aws.String(key),
		Body:        file,
		ContentType: aws.String(fileHeader.Header.Get("Content-Type")),
	})
	if err != nil {
		return "", fmt.Errorf("failed to upload to S3: %w", err)
	}

	// Generate URLs
	fileURL := fmt.Sprintf("https://%s.s3.amazonaws.com/%s", fh.S3Bucket, key)
	cdnURL := fmt.Sprintf("%s/%s", fh.AWSCloudFrontDomain, key)

	// Save to database
	query := `INSERT INTO images (user_id, s3_key, original_filename, mime_type, file_size_bytes, url, cdn_url) 
			  VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`

	var imageID uuid.UUID
	err = fh.DB.QueryRow(query, userID, key, fileHeader.Filename,
		fileHeader.Header.Get("Content-Type"), fileHeader.Size, fileURL, cdnURL).Scan(&imageID)
	if err != nil {
		return "", fmt.Errorf("failed to save to database: %w", err)
	}

	host := os.Getenv("BACKEND_URL")

	// /api/file/get-file/{id}
	params := fmt.Sprintf("/api/file/get-file/%s", imageID)

	url := host + params

	// Return the CDN URL
	return url, nil
}

// uploadVideoForThirdPartyMedia handles video uploads for third-party integrations
func (fh *FileHandler) uploadVideoForThirdPartyMedia(ctx context.Context, userID string, fileHeader *multipart.FileHeader) (string, error) {
	if fileHeader.Size > maxVideoUploadSizeBytes {
		return "", fmt.Errorf("video size exceeds 50MB limit")
	}

	if err := validateVideoContentType(fileHeader.Header.Get("Content-Type")); err != nil {
		return "", err
	}

	file, err := fileHeader.Open()
	if err != nil {
		return "", fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	// Generate S3 key
	key := fmt.Sprintf("videos/%d_%s_%s", time.Now().UnixNano(), userID, fileHeader.Filename)

	// Upload to S3
	_, err = fh.S3Uploader.UploadWithContext(ctx, &s3manager.UploadInput{
		Bucket:      aws.String(fh.S3Bucket),
		Key:         aws.String(key),
		Body:        file,
		ContentType: aws.String(fileHeader.Header.Get("Content-Type")),
	})
	if err != nil {
		return "", fmt.Errorf("failed to upload to S3: %w", err)
	}

	// Save to database and get ID
	id, err := fh.saveMediaToDB(userID, key, fileHeader.Filename,
		fileHeader.Header.Get("Content-Type"), fileHeader.Size, "")
	if err != nil {
		return "", err
	}

	// mux.HandleFunc("GET /api/media/watch?vid={video_id}", fh.HandleMediaStreamingRequest)

	// waterwater

	backend_url := fh.BACKEND_URL

	path := fmt.Sprintf("/api/media/stream?vid=%s", id)

	// Build and return stream URL
	_ = fh.buildMediaStreamURL(id)
	return backend_url + path, nil
}

// uploadAudioForThirdParty handles audio uploads for third-party integrations
func (fh *FileHandler) uploadAudioForThirdParty(ctx context.Context, userID string, fileHeader *multipart.FileHeader) (string, error) {
	if fileHeader.Size > maxAudioUploadSizeBytes {
		return "", fmt.Errorf("audio size exceeds 30MB limit")
	}

	if err := validateAudioContentType(fileHeader.Header.Get("Content-Type")); err != nil {
		return "", err
	}

	file, err := fileHeader.Open()
	if err != nil {
		return "", fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	// Generate S3 key
	key := fmt.Sprintf("audio/%d_%s_%s", time.Now().UnixNano(), userID, fileHeader.Filename)

	// Upload to S3
	_, err = fh.S3Uploader.UploadWithContext(ctx, &s3manager.UploadInput{
		Bucket:      aws.String(fh.S3Bucket),
		Key:         aws.String(key),
		Body:        file,
		ContentType: aws.String(fileHeader.Header.Get("Content-Type")),
	})
	if err != nil {
		return "", fmt.Errorf("failed to upload to S3: %w", err)
	}

	// Save to database and get ID
	id, err := fh.saveMediaToDB(userID, key, fileHeader.Filename,
		fileHeader.Header.Get("Content-Type"), fileHeader.Size, "")
	if err != nil {
		return "", err
	}

	// Build and return stream URL
	streamURL := fh.buildMediaStreamURL(id)
	return streamURL, nil
}

func (fh *FileHandler) GetAllVideosWithUserID(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDContextKey).(string)

	if userID == "" || userID == " " {
		utils.RespondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	rows, err := fh.DB.Query(`
        SELECT id, original_filename, mime_type, file_size_bytes, url, upload_date
        FROM videos
        WHERE user_id = $1
    `, userID)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	defer rows.Close()

	type VideoMetadata struct {
		Vid              string    `json:"vid"`
		OriginalFilename string    `json:"original_filename"`
		MimeType         string    `json:"mime_type"`
		FileSizeBytes    int64     `json:"file_size_bytes"`
		Url              string    `json:"url"`
		UploadDate       time.Time `json:"upload_date"`
	}

	var videos []VideoMetadata

	for rows.Next() {
		var v VideoMetadata
		if err := rows.Scan(&v.Vid, &v.OriginalFilename, &v.MimeType, &v.FileSizeBytes, &v.Url, &v.UploadDate); err != nil {
			utils.RespondError(w, http.StatusInternalServerError, "Internal server error")
			return
		}
		videos = append(videos, v)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]any{
		"status": "success",
		"data":   videos,
	}

	if err = json.NewEncoder(w).Encode(response); err != nil {
		utils.RespondError(w, http.StatusInternalServerError, "Unable to encode to json")
	}
}

// Video Helper functions

func (fh *FileHandler) saveMediaToDB(userId string, s3Key, filename, mimeType string, fileSize int64, url string) (uuid.UUID, error) {
	var id uuid.UUID
	err := fh.DB.QueryRow(`
        INSERT INTO videos (user_id, s3_key, original_filename, mime_type, file_size_bytes, url)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id`,
		userId, s3Key, filename, mimeType, fileSize, url,
	).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to insert video: %w", err)
	}
	return id, nil
}

func (fh *FileHandler) getMediaS3Key(vid string) (string, error) {
	var s3Key string
	err := fh.DB.QueryRow(`SELECT s3_key FROM videos WHERE id = $1`, vid).Scan(&s3Key)
	if err != nil {
		return "", err
	}
	return s3Key, nil
}

func (fh *FileHandler) deleteMediaFromDB(vid string, userID string) error {
	var key string
	err := fh.DB.QueryRow(
		`DELETE FROM videos WHERE id = $1 AND user_id = $2 RETURNING s3_key`,
		vid, userID,
	).Scan(&key)
	if err != nil {
		return fmt.Errorf("failed to delete video from DB: %v", err)
	}

	_, err = fh.S3Client.DeleteObject(&s3.DeleteObjectInput{
		Bucket: aws.String(fh.S3Bucket),
		Key:    aws.String(key),
	})

	if err != nil {
		fmt.Printf("failed to delete object from S3: %v\n", err)
		return fmt.Errorf("unable to delete video from Cloud")
	}

	return nil
}

func validateVideoContentType(contentType string) error {
	allowedTypes := []string{
		"video/mp4",
		"video/webm",
		"video/ogg",
		"video/quicktime",
		"video/x-msvideo",
		"video/x-ms-wmv",
		"video/mpeg",
		"video/3gpp",
		"video/3gpp2",
		"video/x-flv",
		"application/vnd.rn-realmedia",
		"video/x-matroska",
	}

	for _, t := range allowedTypes {
		if contentType == t {
			return nil
		}
	}
	return fmt.Errorf("unsupported video format: %s", contentType)
}
