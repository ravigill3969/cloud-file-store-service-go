package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"strings"
	"time"
)

const (
	ErrCodeBadRequest         = "BAD_REQUEST"
	ErrCodeUnauthorized       = "UNAUTHORIZED"
	ErrCodeForbidden          = "FORBIDDEN"
	ErrCodeNotFound           = "NOT_FOUND"
	ErrCodeConflict           = "CONFLICT"
	ErrCodeValidation         = "VALIDATION_ERROR"
	ErrCodeRateLimit          = "RATE_LIMIT_EXCEEDED"
	ErrCodeInternalError      = "INTERNAL_ERROR"
	ErrCodeServiceUnavailable = "SERVICE_UNAVAILABLE"
)


type APIResponse struct {
	Status      string            `json:"status"`
	Message     string            `json:"message,omitempty"`
	Data        interface{}       `json:"data,omitempty"`
	FieldErrors map[string]string `json:"field_errors,omitempty"`
	Code        string            `json:"code,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
}

func writeJSON(w http.ResponseWriter, statusCode int, resp APIResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if resp.Timestamp.IsZero() {
		resp.Timestamp = time.Now().UTC()
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("ERROR: failed to encode response (status=%d): %v", statusCode, err)
		// Fallback error response if encoding fails
		http.Error(w, `{"status":"error","message":"Failed to encode response"}`, http.StatusInternalServerError)
	}
}

func normalizeData(data []interface{}) interface{} {
	switch len(data) {
	case 0:
		return nil
	case 1:
		return data[0]
	default:
		return data
	}
}

func codeFromStatus(statusCode int) string {
	switch {
	case statusCode >= 500:
		return ErrCodeInternalError
	case statusCode == http.StatusUnauthorized:
		return ErrCodeUnauthorized
	case statusCode == http.StatusForbidden:
		return ErrCodeForbidden
	case statusCode == http.StatusNotFound:
		return ErrCodeNotFound
	case statusCode == http.StatusConflict:
		return ErrCodeConflict
	case statusCode == http.StatusTooManyRequests:
		return ErrCodeRateLimit
	case statusCode >= 400:
		return ErrCodeBadRequest
	default:
		return "OK"
	}
}


func RespondSuccess(w http.ResponseWriter, statusCode int, data ...interface{}) {
	payload := APIResponse{
		Status:  "success",
		Message: http.StatusText(statusCode),
		Data:    normalizeData(data),
		Code:    codeFromStatus(statusCode),
	}
	writeJSON(w, statusCode, payload)
}

func RespondString(w http.ResponseWriter, statusCode int, message string) {
	payload := APIResponse{
		Status:  "success",
		Message: message,
		Code:    codeFromStatus(statusCode),
	}
	writeJSON(w, statusCode, payload)
}

func RespondThirdParty(w http.ResponseWriter, statusCode int, data interface{}) {
	payload := APIResponse{
		Status:  "success",
		Message: http.StatusText(statusCode),
		Data:    data,
		Code:    codeFromStatus(statusCode),
	}
	writeJSON(w, statusCode, payload)
}

//error
func RespondError(w http.ResponseWriter, statusCode int, message string) {
	payload := APIResponse{
		Status:  "error",
		Message: message,
		Code:    codeFromStatus(statusCode),
	}
	writeJSON(w, statusCode, payload)
}

func RespondInternal(w http.ResponseWriter, err error, message string) {
	log.Printf("ERROR: Internal error - %s: %v\nStack trace:\n%s", message, err, debug.Stack())
	payload := APIResponse{
		Status:  "error",
		Message: message,
		Code:    ErrCodeInternalError,
	}
	writeJSON(w, http.StatusInternalServerError, payload)
}


// RespondValidationError helps respond with multiple validation errors at once.
func RespondValidationError(w http.ResponseWriter, message string, fields []string) {
	if message == "" {
		message = "Validation failed"
	}
	if len(fields) > 0 {
		message = fmt.Sprintf("%s: %s", message, strings.Join(fields, ", "))
	}
	payload := APIResponse{
		Status:  "error",
		Message: message,
		Code:    ErrCodeValidation,
	}
	writeJSON(w, http.StatusBadRequest, payload)
}

// RespondFieldErrors returns validation errors with field-specific messages.
func RespondFieldErrors(w http.ResponseWriter, fieldErrors map[string]string) {
	payload := APIResponse{
		Status:      "error",
		Message:     "Validation failed",
		FieldErrors: fieldErrors,
		Code:        ErrCodeValidation,
	}
	writeJSON(w, http.StatusBadRequest, payload)
}
