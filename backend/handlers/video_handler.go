package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"sync"

	pb "github.com/ravigill3969/cloud-file-store-service-video-goGrpc/video"
	middleware "github.com/ravigill3969/cloud-file-store/backend/middlewares"
	"github.com/ravigill3969/cloud-file-store/backend/utils"
	"github.com/redis/go-redis/v9"
)

type VideoHandler struct {
	VideoClient pb.VideoServiceClient
	RedisClient *redis.Client
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

	const chunkSize = 1024 * 1024 * 5 // 5MB

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

			fmt.Println(resp.VideoUrl)

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

	for {
		resp, err := stream.Recv()

		if err == io.EOF {
			break
		}

		if err != nil {
			http.Error(w, "Error streaming video", http.StatusInternalServerError)
			return
		}

		_, err = w.Write(resp.ChunkData)

		if resp.IsLastChunk {
			break
		}

		w.(http.Flusher).Flush()
	}

}
