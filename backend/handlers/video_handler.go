package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"sync"

	"github.com/google/uuid"
	pb "github.com/ravigill3969/cloud-file-store-service-video-goGrpc/video"
	middleware "github.com/ravigill3969/cloud-file-store/backend/middlewares"
	"github.com/ravigill3969/cloud-file-store/backend/utils"
	"github.com/redis/go-redis/v9"
)

type VideoHandler struct {
	VideoClient pb.VideoServiceClient
	RedisClient *redis.Client
	DB          *sql.DB
}

func (v *VideoHandler) VideoUpload(w http.ResponseWriter, r *http.Request) {

	err := r.ParseMultipartForm(50 << 20)
	if err != nil {
		http.Error(w, "Could not parse multipart form", http.StatusBadRequest)
		return
	}

	userID, _ := r.Context().Value(middleware.UserIDContextKey).(string)
	files := r.MultipartForm.File["video"]
	resChan := make(chan string, len(files))
	errChn := make(chan error, len(files))

	const chunkSize = 1024 // 1MB

	var wg sync.WaitGroup

	for _, fh := range files {
		wg.Add(1)

		go func(fh *multipart.FileHeader) {
			defer wg.Done()

			file, err := fh.Open()
			if err != nil {
				errChn <- fmt.Errorf("error opening file %s: %w", fh.Filename, err)
				return
			}
			defer file.Close()

			// Create gRPC stream
			stream, err := v.VideoClient.UploadVideo(r.Context())
			if err != nil {
				errChn <- fmt.Errorf("error creating upload stream for %s: %w", fh.Filename, err)
				return
			}

			buf := make([]byte, chunkSize)
			firstChunk := true
			for {
				n, err := file.Read(buf)
				if err == io.EOF {
					break
				}
				if err != nil {
					errChn <- fmt.Errorf("error reading file %s: %w", fh.Filename, err)
					return
				}

				req := &pb.UploadVideoRequest{
					ChunkData:   buf[:n],
					IsLastChunk: false,
				}

				if firstChunk {
					req.UserId = userID
					req.OriginalFilename = fh.Filename
					req.MimeType = fh.Header.Get("Content-Type")
					firstChunk = false
					req.FileSize = int64(fh.Size)
				}

				if err := stream.Send(req); err != nil {
					errChn <- fmt.Errorf("error sending chunk for %s: %w", fh.Filename, err)
					return
				}
			}

			// Send last chunk signal
			if err := stream.Send(&pb.UploadVideoRequest{
				UserId:           userID,
				OriginalFilename: fh.Filename,
				MimeType:         fh.Header.Get("Content-Type"),
				IsLastChunk:      true,
			}); err != nil {
				errChn <- fmt.Errorf("error sending last chunk for %s: %w", fh.Filename, err)
				return
			}

			// Receive response
			resp, err := stream.CloseAndRecv()
			if err != nil {
				errChn <- fmt.Errorf("error closing stream for %s: %w", fh.Filename, err)
				return
			}

			resChan <- resp.VideoUrl
		}(fh)
	}

	wg.Wait()
	close(resChan)
	close(errChn)

	var successURL []string
	var errMsg []string

	for url := range resChan {

		successURL = append(successURL, url)
	}
	for errmsg := range errChn {
		errMsg = append(errMsg, errmsg.Error())
	}

	// Respond
	if len(errMsg) > 0 {
		http.Error(w, fmt.Sprintf("Errors: %v", errMsg), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := map[string]any{
		"success": successURL,
		"error":   errMsg,
	}

	if err = json.NewEncoder(w).Encode(response); err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Internal server error")
	}
}

func (v *VideoHandler) GetVideoWithIDandServeItInChunks(w http.ResponseWriter, r *http.Request) {

	vid := r.URL.Query().Get("vid")

	fmt.Println(r)

	if vid == "" {
		utils.SendError(w, http.StatusBadRequest, "Invalid Id")
		return
	}

	req := &pb.GetVideoRequest{Vid: vid}

	stream, err := v.VideoClient.GetVideo(r.Context(), req)

	if err != nil {
		http.Error(w, "Video not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "video/mp4")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("Accept-Ranges", "bytes")

	flusher, _ := w.(http.Flusher)

	for {
		resp, err := stream.Recv()

		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "error streaming video", http.StatusInternalServerError)
			return
		}

		if _, err := w.Write(resp.ChunkData); err != nil {
			return
		}
		flusher.Flush()
	}

}

func (v *VideoHandler) DeleteVideoWithUserID(w http.ResponseWriter, r *http.Request) {
	vid := r.URL.Query().Get("vid")
	userId := r.Context().Value(middleware.UserIDContextKey).(string)

	resp, err := v.VideoClient.DeleteVideo(r.Context(), &pb.DeleteVideoRequest{
		UserID: userId,
		Vid:    vid,
	})

	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Intenal server error")
		return
	}

	if resp.Success {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusInternalServerError)

	}

	w.Header().Set("Content-type", "application/json")

	response := map[string]any{
		"Status":  resp.Success,
		"message": resp.Message,
	}

	if err = json.NewEncoder(w).Encode(response); err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Unable to encode to json")
	}

}

func (v *VideoHandler) UploadVideoForThirdParty(w http.ResponseWriter, r *http.Request) {

	// /api/video/upload/{publicKey}/secret/{secretKey}

	parsedUrl := strings.Split(r.URL.Path, "/")

	publicKey := parsedUrl[4]
	secretKey := parsedUrl[6]

	var userID uuid.UUID

	err := v.DB.QueryRow(`SELECT uuid FROM users WHERE public_key = $1 AND secret_key = $2`, &publicKey, &secretKey).Scan(&userID)

	if err != nil {
		utils.SendError(w, http.StatusUnauthorized, "Invalid keys")
		return
	}

	if err := r.ParseMultipartForm(50 << 20); err != nil {
		utils.SendError(w, http.StatusBadRequest, "Could not parse multipart form: ")
		return
	}

	files := r.MultipartForm.File["video"]
	if len(files) == 0 {
		utils.SendError(w, http.StatusBadRequest, "No video file provided")
		return
	}

	fileHeader := files[0]
	file, err := fileHeader.Open()
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Failed to open uploaded file: "+err.Error())
		return
	}
	defer file.Close()

	stream, err := v.VideoClient.UploadVideoFromThirdParty(r.Context())
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Failed to open gRPC stream: "+err.Error())
		return
	}

	buf := make([]byte, 1024)
	firstChunk := true

	for {
		n, err := file.Read(buf)
		if err != nil && err != io.EOF {
			utils.SendError(w, http.StatusInternalServerError, "Error reading file: "+err.Error())
			return
		}

		if n == 0 {
			break
		}

		req := &pb.UploadVideoFromThirdPartyRequest{
			ChunkData:   buf[:n],
			IsLastChunk: false,
		}

		if firstChunk {
			req.OriginalFilename = fileHeader.Filename
			req.MimeType = fileHeader.Header.Get("Content-Type")
			req.FileSize = int64(fileHeader.Size)
			firstChunk = false
			req.UserId = userID.String()

		}

		if err := stream.Send(req); err != nil {
			utils.SendError(w, http.StatusInternalServerError, "Failed to send chunk: "+err.Error())
			return
		}
	}

	lastReq := &pb.UploadVideoFromThirdPartyRequest{

		IsLastChunk: true,
	}

	if err := stream.Send(lastReq); err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Failed to send last chunk: "+err.Error())
		return
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Failed to receive response: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := map[string]any{
		"success": resp.VideoUrl,
		"error":   resp.ErrorMessage,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Failed to encode response: "+err.Error())
	}
}

func (v *VideoHandler) DeleteVideoForThirdParty(w http.ResponseWriter, r *http.Request) {
	parsedUrl := strings.Split(r.URL.Path, "/")

	publicKey := parsedUrl[4]
	secretKey := parsedUrl[6]
	vid := parsedUrl[7]

	var userID uuid.UUID

	err := v.DB.QueryRow(`SELECT uuid FROM users WHERE public_key = $1 AND secret_key = $2`, &publicKey, &secretKey).Scan(&userID)

	if err != nil {
		utils.SendError(w, http.StatusUnauthorized, "Invalid keys")
		return
	}

	resp, err := v.VideoClient.DeleteVideoFromThirdParty(r.Context(), &pb.DeleteVideoFromThirdPartyRequest{
		Vid:    vid,
		UserId: userID.String(),
	})

	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	if !resp.Success {
		utils.SendError(w, http.StatusInternalServerError, resp.Message)
		return
	}

	utils.SendJSON(w, http.StatusOK, resp.Message)
}

func (v *VideoHandler) GetAllVideosWithUserID(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(middleware.UserIDContextKey).(string)

	if userID == " " {
		utils.SendError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	resp, err := v.VideoClient.GetAllVideosWithUserID(r.Context(), &pb.GetAllVideosWithUserIDRequest{
		UserId: userID,
	})

	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	utils.SendJSON(w, http.StatusOK, resp)
}
