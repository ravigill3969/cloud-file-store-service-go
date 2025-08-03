package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
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
	"github.com/aws/aws-sdk-go/service/s3/s3manager/s3manageriface"
	"github.com/google/uuid"
	middleware "github.com/ravigill3969/cloud-file-store/middlewares"
	"github.com/ravigill3969/cloud-file-store/models"
	"github.com/ravigill3969/cloud-file-store/utils"
	"github.com/redis/go-redis/v9"
)

const (
	fileSizeLimitPerDayInMb = 344
)

type FileHandler struct {
	DB         *sql.DB
	S3Uploader s3manageriface.UploaderAPI
	S3Client   s3iface.S3API
	S3Bucket   string
	Redis      *redis.Client
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
	// 	ID           uuid.UUID `json:"id"`
	// PublicKey    string    `json:"public_key"`
	// SecretKey    string    `json:"secret_key"`
	// Username     string    `json:"username"`
	// Email        string    `json:"email"`
	// PostAPICalls int16     `json:"post_api_calls"`

	fmt.Println(err)

	if user.SecretKey != "" && secretKey != user.SecretKey {
		http.Error(w, "Invalid public or secret key", http.StatusUnauthorized)
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

	url := os.Getenv("BACKEND_URL")
	imageURL := fmt.Sprintf("%s/api/file/get-file/%s", url, fileUpload.Id)

	utils.SendJSONToThirdParty(w, http.StatusOK, map[string]string{
		"url": imageURL,
	})

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

func (fh *FileHandler) GetFileEditStoreInS3ThenInPsqlWithWidthAndSize(w http.ResponseWriter, r *http.Request) {
	parsedURL := strings.Split(r.URL.Path, "/")

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
		return
	}

	str, key, err := LamdaMagicHere(image.S3Key, widthStr, heightStr)
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
		http.Error(w, "Failed to insert image", http.StatusInternalServerError)
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
		http.Error(w, "Failed to update, API quota limit reached", http.StatusInternalServerError)
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

	url := os.Getenv("BACKEND_URL")
	imageURL := fmt.Sprintf("%s/api/file/get-file/%s", url, imageID)

	utils.SendJSONToThirdParty(w, http.StatusOK, map[string]string{
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
		utils.SendError(w, http.StatusUnauthorized, "Unauthorized!")
		return
	}
	if userId == "" {
		utils.SendError(w, http.StatusUnauthorized, "Unauthorized!")
		return
	}

	rows, err := fh.DB.Query(`SELECT id, original_filename,mime_type,upload_date,width, height FROM images WHERE user_id = $1 AND deleted = FALSE`, userId)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Query failed!")
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
			utils.SendError(w, http.StatusInternalServerError, "Scan failed!")
			return
		}
		img = append(img, image)
	}

	if err = rows.Err(); err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Error reading rows!")
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
		http.Error(w, "Failed to send response", http.StatusInternalServerError)
	}

}

func (fh *FileHandler) UploadFilesWithGoRoutines(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		fmt.Println("ParseMultipartForm error:", err)
		http.Error(w, "Could not parse multipart form", http.StatusBadRequest)
		return
	}

	files := r.MultipartForm.File["file"]

	if len(files) == 0 {
		http.Error(w, "No files uploaded", http.StatusBadRequest)
		return
	}

	userID, ok := r.Context().Value(middleware.UserIDContextKey).(string)

	if !ok {
		log.Printf("Error: User ID not found in context")
		http.Error(w, "Unauthorized: User ID not provided", http.StatusUnauthorized)
		return
	}

	row := fh.DB.QueryRow("SELECT username, email, public_key, secret_key ,account_type FROM users WHERE uuid = $1", &userID)

	var user models.UserForFileUpload

	err = row.Scan(
		&user.Username,
		&user.Email,
		&user.PublicKey,
		&user.SecretKey,
		&user.AccountType,
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

	success := make(chan models.UploadGoRoutines, len(files))
	errChn := make(chan error, len(files))

	var wg sync.WaitGroup

	for _, fileHeader := range files {
		wg.Add(1)
		go func(f *multipart.FileHeader) {
			defer wg.Done()
			if f.Filename == "" {
				errChn <- fmt.Errorf("filename not defined %s", f.Filename)
				return
			}

			sizeInBytes := fileHeader.Size
			sizeInMB := float64(sizeInBytes) / (1024 * 1024)

			res := fh.Redis.Get(r.Context(), userID+"file-size-limit")

			val, err := res.Float64()
			fmt.Println(err)
			if err != nil {
				if err == redis.Nil {
					errChn <- fmt.Errorf("daily limit reached %s", f.Filename)
					val = sizeInMB
				} else {
					errChn <- fmt.Errorf("internal server error %s", f.Filename)
				}

			}

			fmt.Println(val)

			if val > fileSizeLimitPerDayInMb {
				errChn <- fmt.Errorf("daily limit reached %s", f.Filename)
				return
			}

			fh.Redis.Set(r.Context(), userID+"file-size-limit", val+sizeInMB, 24*time.Hour)

			err = validateContentType(f.Header.Get("Content-Type"))

			if err != nil {
				errChn <- fmt.Errorf("invalid file type %s", f.Filename)
				return
			}

			file, err := f.Open()

			if err != nil {
				errChn <- fmt.Errorf("unable to open file %s", f.Filename)
				return
			}

			defer file.Close()

			fileBytes, err := io.ReadAll(file)
			if err != nil {
				errChn <- fmt.Errorf("unable to read file %s", f.Filename)
				return
			}

			key := "uploads/" + strconv.FormatInt(time.Now().UnixNano(), 10) + "_" + userID + "_" + f.Filename

			url, err := fh.CreatePresignedUploadRequest(f.Filename, f.Header.Get("Content-Type"), key)

			if err != nil {
				fmt.Println(err)
				errChn <- fmt.Errorf("internal server error with file %s", f.Filename)
				return
			}

			reqHttp, err := http.NewRequest("PUT", *url, bytes.NewReader(fileBytes))

			if err != nil {
				fmt.Println(err)

				errChn <- fmt.Errorf("internal server error with file %s", f.Filename)
				return
			}

			reqHttp.Header.Set("Content-Type", f.Header.
				Get("Content-Type"))

			client := &http.Client{}

			resp, err := client.Do(reqHttp)

			if err != nil {
				fmt.Println(err)

				errChn <- fmt.Errorf("unable to upload file %s", f.Filename)
				return
			}

			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				fmt.Println("err")

				errChn <- fmt.Errorf("internal server error %s", f.Filename)
				return
			}

			fileURL := "https://" + fh.S3Bucket + ".s3.amazonaws.com/" + key
			success <- models.UploadGoRoutines{Url: fileURL, OriginalFilename: f.Filename, MimeType: f.Header.Get("Content-Type"), Width: 0, Height: 0, S3Key: key, FileSize: f.Size}

		}(fileHeader)

		wg.Wait()
	}
	close(success)
	close(errChn)

	var uploaded []models.UploadGoRoutines

	var uploadedFiles []string
	for imgSuccess := range success {
		uploadedFiles = append(uploadedFiles, imgSuccess.OriginalFilename)
		uploaded = append(uploaded, models.UploadGoRoutines{
			Url:              imgSuccess.Url,
			OriginalFilename: imgSuccess.OriginalFilename,
			MimeType:         imgSuccess.MimeType,
			Width:            imgSuccess.Width,
			Height:           imgSuccess.Height,
			S3Key:            imgSuccess.S3Key,
			FileSize:         imgSuccess.FileSize,
		})
	}

	err = fh.SaveUploadedImages(uploaded, userID)

	if err != nil {
		fmt.Println(err)
		utils.SendError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	var errorMessages []string
	for err := range errChn {
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
		}
	}
	response := map[string]any{
		"uploaded_files":  uploadedFiles,
		"failed_file_err": errorMessages,
	}

	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Internal server errors")
		return
	}

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
		INSERT INTO images (user_id, url, original_filename, mime_type, width, height, s3_key,file_size_bytes)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, img := range images {
		_, err = stmt.Exec(userID, img.Url, img.OriginalFilename, img.MimeType, img.Width, img.Height, img.S3Key, img.FileSize)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (fh *FileHandler) ServeFileWithIDForUI(w http.ResponseWriter, r *http.Request) {
	parsedURL := strings.Split(r.URL.Path, "/")

	if len(parsedURL) < 4 {
		http.Error(w, "Invalid URL structure", http.StatusBadRequest)
		return
	}

	photoID := parsedURL[4]

	if photoID == "" {
		http.Error(w, "Invalid id", http.StatusBadRequest)
		return
	}

	row2 := fh.DB.QueryRow(`SELECT url FROM images WHERE id = $1`, photoID)

	var url string

	err := row2.Scan(
		&url,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Invalid image id", http.StatusBadRequest)
		} else {
			http.Error(w, "Image not found", http.StatusNotFound)

		}

		fmt.Println(err)
		return
	}

	resp, err := http.Get(url)

	fmt.Println(err)
	fmt.Println(resp.Header.Get("Content-Type"))

	if err != nil || resp.StatusCode != http.StatusOK {
		http.Error(w, "Failed to fetch image", http.StatusBadGateway)
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
		http.Error(w, "Invalid URL structure", http.StatusBadRequest)
		return
	}

	photoID := parsedURL[4]
	if photoID == "" {
		http.Error(w, "Invalid id", http.StatusBadRequest)
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

	log.Printf("Served image %s from cache (%d bytes)", photoID, len(imageBytes))
	return true
}

func (fh *FileHandler) serveFromSource(w http.ResponseWriter, r *http.Request, photoID string) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	fmt.Println(photoID)
	row := fh.DB.QueryRowContext(ctx, `SELECT url FROM images WHERE id = $1`, photoID)
	var url string
	err := row.Scan(&url)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Image not found", http.StatusNotFound)
		} else {
			log.Printf("Database error for image %s: %v", photoID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		log.Printf("Error fetching image from %s: %v", url, err)
		http.Error(w, "Failed to fetch image", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Non-200 status code %d when fetching %s", resp.StatusCode, url)
		http.Error(w, "Failed to fetch image", http.StatusBadGateway)
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

	log.Printf("Served image %s from source (%d bytes)", photoID, cacheBuffer.Len())

	go func() {
		if err := fh.cacheImageInRedis(photoID, contentType, cacheBuffer.Bytes()); err != nil {
			log.Printf("Error caching image %s: %v", photoID, err)
		} else {
			log.Printf("Successfully cached image %s (%d bytes)", photoID, cacheBuffer.Len())
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
		utils.SendError(w, http.StatusBadRequest, "Missing 'key' parameter")
		return
	}

	var s3key string

	err := fh.DB.QueryRow(`SELECT s3_key FROM images WHERE id = $1 AND deleted = FALSE`, id).Scan(&s3key)

	if err != nil {
		utils.SendError(w, http.StatusNotFound, "Not found!")
		return
	}

	output, err := fh.S3Client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(fh.S3Bucket),
		Key:    aws.String(s3key),
	})
	if err != nil {
		http.Error(w, "Failed to get object from S3: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer output.Body.Close()

	filename := path.Base(s3key)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Type", aws.StringValue(output.ContentType))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", *output.ContentLength))

	_, err = io.Copy(w, output.Body)
	if err != nil {
		http.Error(w, "Failed to stream file", http.StatusInternalServerError)
		return
	}
}

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
			utils.SendError(w, http.StatusNotFound, "Not found")
		} else {
			utils.SendError(w, http.StatusInternalServerError, "Internal server error")
		}
		return
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Could not determine deletion result")
		return
	}

	if rowsAffected == 0 {
		utils.SendError(w, http.StatusNotFound, "No image deleted (maybe wrong ID or unauthorized)")
		return
	}

	// fh.S3Client.DeleteObject(&s3.DeleteObjectInput{
	// 	Bucket: aws.String(fh.S3Bucket),
	// 	Key:    aws.String(s3Key),
	// })

	// if err != nil {
	// 	return fmt.Errorf("failed to delete object from S3: %w", err)
	// }

	// // Optional: Wait for deletion to be confirmed (for consistency)
	// err = fh.S3Client.WaitUntilObjectNotExists(ctx, &s3.HeadObjectInput{
	// 	Bucket: aws.String(h.S3Bucket),
	// 	Key:    aws.String(s3Key),
	// })
	// if err != nil {
	// 	return fmt.Errorf("delete confirmed failed: %w", err)
	// }

	utils.SendJSON(w, http.StatusOK, "Image deleted successfully")

	go removeImageFromRedis(imageID, fh.Redis)
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

func (fh *FileHandler) GetAllImagesWithUserIDWhichAreDeletedEqFalse(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.UserIDContextKey).(string)

	if !ok {
		utils.SendError(w, http.StatusUnauthorized, "Please login to perform this action.")
		return
	}

	if userID == "" {
		utils.SendError(w, http.StatusUnauthorized, "Please login to perform this action.")
		return
	}

	rows, err := fh.DB.Query(`SELECT id FROM images WHERE deleted = true AND user_id = $1`, userID)
	var images []string

	defer rows.Close()

	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	for rows.Next() {
		var id string

		if err := rows.Scan(&id); err != nil {
			utils.SendError(w, http.StatusInternalServerError, "Internal server error")
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
		utils.SendError(w, http.StatusInternalServerError, "Unable to encode to json.")
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (fh *FileHandler) RecoverDeletedImage(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.UserIDContextKey).(string)
	
	if !ok {
		utils.SendError(w, http.StatusUnauthorized, "Please login to perform this action.")
		return
	}
	
	if userID == "" {
		utils.SendError(w, http.StatusUnauthorized, "Please login to perform this action.")
		return
	}
	
	id := r.URL.Query().Get("id")
	
	
	if id == "" {
		utils.SendError(w, http.StatusBadRequest, "id is required")
		return
	}
	
	result, err := fh.DB.Exec(`UPDATE images SET deleted = false, deleted_at = NULL WHERE id = $1 AND user_id = $2`, id, userID)
	
	fmt.Println(err)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	rowsAffected, err := result.RowsAffected()

	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	if rowsAffected == 0 {
		utils.SendError(w, http.StatusUnauthorized, "No image found")
		return
	}

	utils.SendJSON(w, http.StatusOK)

}
