package handlers

// import (
// 	"database/sql"
// 	"encoding/json"
// 	"fmt"
// 	"io"
// 	"mime/multipart"
// 	"net/http"
// 	"strings"
// 	"sync"
// 	"time"

// 	"github.com/aws/aws-sdk-go/aws"
// 	"github.com/aws/aws-sdk-go/service/s3"
// 	"github.com/aws/aws-sdk-go/service/s3/s3manager"
// 	"github.com/google/uuid"
// 	middleware "github.com/ravigill3969/cloud-file-store/backend/middlewares"
// 	"github.com/ravigill3969/cloud-file-store/backend/utils"
// 	"github.com/redis/go-redis/v9"
// )

// type VideoHandler struct {
// 	S3Uploader          *s3manager.Uploader
// 	S3Client            *s3.S3
// 	S3Bucket            string
// 	RedisClient         *redis.Client
// 	DB                  *sql.DB
// 	AWSCloudFrontDomain string
// }

// func (v *VideoHandler) VideoUpload(w http.ResponseWriter, r *http.Request) {
// 	err := r.ParseMultipartForm(50 << 20) // 50 MB
// 	if err != nil {
// 		utils.SendError(w, http.StatusBadRequest, "Could not parse multipart form")
// 		return
// 	}

// 	userID, _ := r.Context().Value(middleware.UserIDContextKey).(string)
// 	files := r.MultipartForm.File["video"]

// 	type uploadResult struct {
// 		Filename string
// 		URL      string
// 		Error    error
// 	}

// 	resChan := make(chan uploadResult, len(files))
// 	var wg sync.WaitGroup

// 	for _, fh := range files {
// 		wg.Add(1)

// 		go func(fh *multipart.FileHeader) {
// 			defer wg.Done()

// 			if err := validateVideoContentType(fh.Header.Get("Content-Type")); err != nil {
// 				resChan <- uploadResult{Filename: fh.Filename, Error: err}
// 				return
// 			}

// 			file, err := fh.Open()
// 			if err != nil {
// 				resChan <- uploadResult{Filename: fh.Filename, Error: fmt.Errorf("error opening file %s: %w", fh.Filename, err)}
// 				return
// 			}
// 			defer file.Close()

// 			key := fmt.Sprintf("video/%s-%s-%s", userID, time.Now().Format("20060102-150405"), fh.Filename)

// 			// Upload to S3
// 			_, err = v.S3Uploader.Upload(&s3manager.UploadInput{
// 				Bucket: aws.String(v.S3Bucket),
// 				Key:    aws.String(key),
// 				Body:   file,
// 			})
// 			if err != nil {
// 				resChan <- uploadResult{Filename: fh.Filename, Error: fmt.Errorf("error uploading %s to S3: %w", fh.Filename, err)}
// 				return
// 			}

// 			// Construct URL
// 			url := fmt.Sprintf("https://%s.s3.amazonaws.com/%s", v.S3Bucket, key)

// 			// Save to DB
// 			id, err := v.saveToDB(userID, key, fh.Filename, fh.Header.Get("Content-Type"), fh.Size, url)
// 			if err != nil {
// 				resChan <- uploadResult{Filename: fh.Filename, Error: fmt.Errorf("error saving %s to DB: %w", fh.Filename, err)}
// 				return
// 			}

// 			// Return the watch URL as per original implementation
// 			watchURL := fmt.Sprintf("http://localhost:8080/api/video/watch?vid=%s", id.String())
// 			resChan <- uploadResult{Filename: fh.Filename, URL: watchURL}
// 		}(fh)
// 	}

// 	wg.Wait()
// 	close(resChan)

// 	var successURL []string
// 	var errMsg []string

// 	for res := range resChan {
// 		if res.Error != nil {
// 			errMsg = append(errMsg, res.Error.Error())
// 		} else {
// 			successURL = append(successURL, res.URL)
// 		}
// 	}

// 	if len(errMsg) > 0 {
// 		utils.SendError(w, http.StatusInternalServerError, fmt.Sprintf("Errors: %v", errMsg))
// 		return
// 	}

// 	w.Header().Set("Content-type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	response := map[string]any{
// 		"success": successURL,
// 		"error":   errMsg,
// 	}

// 	if err = json.NewEncoder(w).Encode(response); err != nil {
// 		utils.SendError(w, http.StatusInternalServerError, "Internal server error")
// 	}
// }

// func (v *VideoHandler) GetVideoWithIDandServeItInChunks(w http.ResponseWriter, r *http.Request) {
// 	vid := r.URL.Query().Get("vid")
// 	if vid == "" {
// 		utils.SendError(w, http.StatusBadRequest, "Invalid Id")
// 		return
// 	}

// 	s3Key, err := v.getS3Key(vid)
// 	if err != nil {
// 		utils.SendError(w, http.StatusNotFound, "Video not found")
// 		return
// 	}

// 	rangeHeader := r.Header.Get("Range")
// 	input := &s3.GetObjectInput{
// 		Bucket: aws.String(v.S3Bucket),
// 		Key:    aws.String(s3Key),
// 	}
// 	if rangeHeader != "" {
// 		input.Range = aws.String(rangeHeader)
// 	}

// 	resp, err := v.S3Client.GetObject(input)
// 	if err != nil {
// 		utils.SendError(w, http.StatusInternalServerError, "Error fetching video")
// 		return
// 	}
// 	defer resp.Body.Close()

// 	if resp.ContentLength != nil {
// 		w.Header().Set("Content-Length", fmt.Sprintf("%d", *resp.ContentLength))
// 	}
// 	if resp.ContentType != nil {
// 		w.Header().Set("Content-Type", *resp.ContentType)
// 	}
// 	if resp.ContentRange != nil {
// 		w.Header().Set("Content-Range", *resp.ContentRange)
// 		w.WriteHeader(http.StatusPartialContent)
// 	} else {
// 		w.WriteHeader(http.StatusOK)
// 	}

// 	w.Header().Set("Accept-Ranges", "bytes")

// 	_, err = io.Copy(w, resp.Body)
// 	if err != nil {
// 		return
// 	}
// }

// func (v *VideoHandler) DeleteVideoWithUserID(w http.ResponseWriter, r *http.Request) {
// 	vid := r.URL.Query().Get("vid")
// 	userId := r.Context().Value(middleware.UserIDContextKey).(string)

// 	err := v.deleteVideo(vid, userId)
// 	if err != nil {
// 		utils.SendError(w, http.StatusInternalServerError, err.Error())
// 		return
// 	}

// 	utils.SendString(w, http.StatusOK, "video deleted successfully")
// }

// func (v *VideoHandler) UploadVideoForThirdParty(w http.ResponseWriter, r *http.Request) {
// 	parsedUrl := strings.Split(r.URL.Path, "/")
// 	if len(parsedUrl) < 7 {
// 		utils.SendError(w, http.StatusBadRequest, "Invalid URL format")
// 		return
// 	}
// 	publicKey := parsedUrl[4]
// 	secretKey := parsedUrl[6]

// 	var userID uuid.UUID
// 	err := v.DB.QueryRow(`SELECT uuid FROM users WHERE public_key = $1 AND secret_key = $2`, publicKey, secretKey).Scan(&userID)
// 	if err != nil {
// 		utils.SendError(w, http.StatusUnauthorized, "Invalid keys")
// 		return
// 	}

// 	if err := r.ParseMultipartForm(50 << 20); err != nil {
// 		utils.SendError(w, http.StatusBadRequest, "Could not parse multipart form")
// 		return
// 	}

// 	files := r.MultipartForm.File["video"]
// 	if len(files) == 0 {
// 		utils.SendError(w, http.StatusBadRequest, "No video file provided")
// 		return
// 	}

// 	fileHeader := files[0]
// 	if fileHeader.Size > 52428800 { // 50MB
// 		utils.SendError(w, http.StatusBadRequest, "File size limit is 50mb")
// 		return
// 	}

// 	if err := validateVideoContentType(fileHeader.Header.Get("Content-Type")); err != nil {
// 		utils.SendError(w, http.StatusBadRequest, err.Error())
// 		return
// 	}

// 	file, err := fileHeader.Open()
// 	if err != nil {
// 		utils.SendError(w, http.StatusInternalServerError, "Failed to open uploaded file: "+err.Error())
// 		return
// 	}
// 	defer file.Close()

// 	key := fmt.Sprintf("video/%s-%s-%s", userID, time.Now().Format("20060102-150405"), fileHeader.Filename)

// 	_, err = v.S3Uploader.Upload(&s3manager.UploadInput{
// 		Bucket: aws.String(v.S3Bucket),
// 		Key:    aws.String(key),
// 		Body:   file,
// 	})
// 	if err != nil {
// 		utils.SendError(w, http.StatusInternalServerError, "Failed to upload to S3: "+err.Error())
// 		return
// 	}

// 	url := fmt.Sprintf("https://%s.s3.amazonaws.com/%s", v.S3Bucket, key)
// 	id, err := v.saveToDB(userID.String(), key, fileHeader.Filename, fileHeader.Header.Get("Content-Type"), fileHeader.Size, url)
// 	if err != nil {
// 		utils.SendError(w, http.StatusInternalServerError, "Internal server error")
// 		return
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	response := map[string]any{
// 		"success": fmt.Sprintf("http://localhost:8080/api/video/watch/?vid=%s", id.String()),
// 		"error":   "",
// 	}

// 	if err := json.NewEncoder(w).Encode(response); err != nil {
// 		utils.SendError(w, http.StatusInternalServerError, "Failed to encode response: "+err.Error())
// 	}
// }

// func (v *VideoHandler) DeleteVideoForThirdParty(w http.ResponseWriter, r *http.Request) {
// 	parsedUrl := strings.Split(r.URL.Path, "/")
// 	if len(parsedUrl) < 8 {
// 		utils.SendError(w, http.StatusBadRequest, "Invalid URL format")
// 		return
// 	}

// 	publicKey := parsedUrl[4]
// 	secretKey := parsedUrl[6]
// 	vid := parsedUrl[7]

// 	var userID uuid.UUID
// 	err := v.DB.QueryRow(`SELECT uuid FROM users WHERE public_key = $1 AND secret_key = $2`, publicKey, secretKey).Scan(&userID)
// 	if err != nil {
// 		utils.SendError(w, http.StatusUnauthorized, "Invalid keys")
// 		return
// 	}

// 	err = v.deleteVideo(vid, userID.String())
// 	if err != nil {
// 		utils.SendError(w, http.StatusInternalServerError, err.Error())
// 		return
// 	}

// 	utils.SendJSON(w, http.StatusOK, "video deleted successfully")
// }

// func (v *VideoHandler) GetAllVideosWithUserID(w http.ResponseWriter, r *http.Request) {
// 	userID, _ := r.Context().Value(middleware.UserIDContextKey).(string)

// 	if userID == "" || userID == " " {
// 		utils.SendError(w, http.StatusUnauthorized, "Unauthorized")
// 		return
// 	}

// 	rows, err := v.DB.Query(`
//         SELECT id, original_filename, mime_type, file_size_bytes, url, upload_date
//         FROM videos
//         WHERE user_id = $1
//     `, userID)
// 	if err != nil {
// 		utils.SendError(w, http.StatusInternalServerError, "Internal server error")
// 		return
// 	}
// 	defer rows.Close()

// 	type VideoMetadata struct {
// 		Vid              string    `json:"vid"`
// 		OriginalFilename string    `json:"original_filename"`
// 		MimeType         string    `json:"mime_type"`
// 		FileSizeBytes    int64     `json:"file_size_bytes"`
// 		Url              string    `json:"url"`
// 		UploadDate       time.Time `json:"upload_date"`
// 	}

// 	var videos []VideoMetadata

// 	for rows.Next() {
// 		var v VideoMetadata
// 		if err := rows.Scan(&v.Vid, &v.OriginalFilename, &v.MimeType, &v.FileSizeBytes, &v.Url, &v.UploadDate); err != nil {
// 			utils.SendError(w, http.StatusInternalServerError, "Internal server error")
// 			return
// 		}
// 		videos = append(videos, v)
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)

// 	response := map[string]any{
// 		"status": "success",
// 		"data":   videos,
// 	}

// 	if err = json.NewEncoder(w).Encode(response); err != nil {
// 		utils.SendError(w, http.StatusInternalServerError, "Unable to encode to json")
// 	}
// }

// // Helper functions

// func (v *VideoHandler) saveToDB(userId string, s3Key, filename, mimeType string, fileSize int64, url string) (uuid.UUID, error) {
// 	var id uuid.UUID
// 	err := v.DB.QueryRow(`
//         INSERT INTO videos (user_id, s3_key, original_filename, mime_type, file_size_bytes, url)
//         VALUES ($1, $2, $3, $4, $5, $6)
//         RETURNING id`,
// 		userId, s3Key, filename, mimeType, fileSize, url,
// 	).Scan(&id)
// 	if err != nil {
// 		return uuid.Nil, fmt.Errorf("failed to insert video: %w", err)
// 	}
// 	return id, nil
// }

// func (v *VideoHandler) getS3Key(vid string) (string, error) {
// 	var s3Key string
// 	err := v.DB.QueryRow(`SELECT s3_key FROM videos WHERE id = $1`, vid).Scan(&s3Key)
// 	if err != nil {
// 		return "", err
// 	}
// 	return s3Key, nil
// }

// func (v *VideoHandler) deleteVideo(vid string, userID string) error {
// 	var key string
// 	err := v.DB.QueryRow(
// 		`DELETE FROM videos WHERE id = $1 AND user_id = $2 RETURNING s3_key`,
// 		vid, userID,
// 	).Scan(&key)
// 	if err != nil {
// 		return fmt.Errorf("failed to delete video from DB: %v", err)
// 	}

// 	_, err = v.S3Client.DeleteObject(&s3.DeleteObjectInput{
// 		Bucket: aws.String(v.S3Bucket),
// 		Key:    aws.String(key),
// 	})

// 	if err != nil {
// 		fmt.Printf("failed to delete object from S3: %v\n", err)
// 		return fmt.Errorf("unable to delete video from Cloud")
// 	}

// 	return nil
// }

// func validateVideoContentType(contentType string) error {
// 	allowedTypes := []string{
// 		"video/mp4",
// 		"video/webm",
// 		"video/ogg",
// 		"video/quicktime",
// 		"video/x-msvideo",
// 		"video/x-ms-wmv",
// 		"video/mpeg",
// 		"video/3gpp",
// 		"video/3gpp2",
// 		"video/x-flv",
// 		"application/vnd.rn-realmedia",
// 		"video/x-matroska",
// 	}

// 	for _, t := range allowedTypes {
// 		if contentType == t {
// 			return nil
// 		}
// 	}
// 	return fmt.Errorf("unsupported video format: %s", contentType)
// }
