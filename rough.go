package cloudfilestoreservicego

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

	"github.com/ravigill3969/cloud-file-store/models"
	"github.com/ravigill3969/cloud-file-store/utils"
	"github.com/stripe/stripe-go/checkout/session"
	"github.com/stripe/stripe-go/v82"
)

func (s *Stripe) VerifyCheckoutSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	sess, err := session.Get(req.SessionID, nil)

	// userData := sess.Metadata["userID"]

	if err != nil {
		utils.SendError(w, http.StatusBadRequest, "Invalid session ID")
		return
	}

	if sess.PaymentStatus != stripe.CheckoutSessionPaymentStatusPaid {
		utils.SendError(w, http.StatusBadRequest, "Payment not completed")
		return
	}

	userID, ok := r.Context().Value(middleware.UserIDContextKey).(string)

	if !ok {
		log.Printf("Error: User ID not found in context")
		http.Error(w, "Unauthorized: User ID not provided", http.StatusUnauthorized)
		return
	}

	customerID := sess.Customer.ID
	subscriptionID := sess.Subscription.ID

	_, err = s.Db.Exec(`
    UPDATE users
    SET post_api_calls = 500,
        get_api_calls = 500,
        edit_api_calls = 50,
        account_type = 'basic',
		stripe_customer_id= $1,
		stripe_subscription_id= $2
    WHERE uuid = $3
`, customerID, subscriptionID, userID)

	fmt.Println(err)
	if err != nil {
		if err == sql.ErrNoRows {
			utils.SendError(w, http.StatusNotFound, "Not found!")
		} else {
			utils.SendError(w, http.StatusInternalServerError, "Internal server error")
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "verified"})
}

func (fh *FileHandler) UploadFile(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Could not parse multipart form", http.StatusBadRequest)
		return
	}

	files := r.MultipartForm.File["file"]

	if len(files) == 0 {
		http.Error(w, "No files uploaded", http.StatusBadRequest)
		return
	}

	var arr []string

	for _, fileHeader := range files {

		if fileHeader.Filename == "" {
			http.Error(w, "Filename missing in upload", http.StatusBadRequest)
			return
		}

		file, err := fileHeader.Open()

		if err != nil {
			http.Error(w, "File not provided", http.StatusBadRequest)
			return
		}

		defer file.Close()

		fileBytes, err := io.ReadAll(file)
		if err != nil {
			http.Error(w, "Error reading file", http.StatusInternalServerError)
			return
		}

		userID, ok := r.Context().Value(middleware.UserIDContextKey).(string)

		if !ok {
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
				http.Error(w, "User not found", http.StatusNotFound)
			} else {
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

		arr = append(arr, fileURL)

		query := `INSERT INTO images (user_id , s3_key, original_filename, mime_type, file_size_bytes, url ) VALUES ($1, $2, $3, $4, $5, $6) RETURNING url, original_filename, id`

		var fileUpload models.UploadFile

		err = fh.DB.QueryRow(query, userID, key, fileHeader.Filename, fileHeader.Header.Get("Content-Type"), fileHeader.Size, fileURL).Scan(&fileUpload.URL, &fileUpload.OriginalFilename, &fileUpload.Id)

		if err != nil {
			http.Error(w, "Unable to save data", http.StatusInternalServerError)
			return
		}
	}

	utils.SendJSON(w, http.StatusOK, arr)

}
