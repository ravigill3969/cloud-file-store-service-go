package handlers

import (
	"fmt"
	"io"
	"mime/multipart"
	"net/http"

	pb "github.com/ravigill3969/cloud-file-store-service-video-goGrpc/video"
	middleware "github.com/ravigill3969/cloud-file-store/backend/middlewares"
	"github.com/redis/go-redis/v9"
)

type VideoHandler struct {
	VideoClient pb.VideoServiceClient
	RedisClient *redis.Client
}

func (v *VideoHandler) VideoUpload(w http.ResponseWriter, r *http.Request) {
	type result struct {
		URL string
		Err error
	}

	err := r.ParseMultipartForm(50 << 20)
	if err != nil {
		http.Error(w, "Could not parse multipart form", http.StatusBadRequest)
		return
	}

	userID, _ := r.Context().Value(middleware.UserIDContextKey).(string)
	files := r.MultipartForm.File["video"]
	resChan := make(chan result, len(files))

	const chunkSize = 1024 * 1024 // 1MB per chunk

	for _, fh := range files {
		go func(fh *multipart.FileHeader) {
			file, err := fh.Open()
			if err != nil {
				resChan <- result{"", err}
				return
			}
			defer file.Close()

			// Create gRPC stream
			stream, err := v.VideoClient.UploadVideo(r.Context())
			if err != nil {
				resChan <- result{"", err}
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
					resChan <- result{"", err}
					return
				}

				req := &pb.UploadVideoRequest{
					UserId:           userID,
					OriginalFilename: fh.Filename,
					MimeType:         fh.Header.Get("Content-Type"),
					ChunkData:        buf[:n],
					IsLastChunk:      false,
				}

				if firstChunk {
					firstChunk = false
				}

				// Send chunk
				if err := stream.Send(req); err != nil {
					resChan <- result{"", err}
					return
				}
			}

			// Send last chunk signal
			if err := stream.Send(&pb.UploadVideoRequest{
				UserId:           userID,
				OriginalFilename: fh.Filename,
				MimeType:         fh.Header.Get("Content-Type"),
				ChunkData:        nil,
				IsLastChunk:      true,
			}); err != nil {
				resChan <- result{"", err}
				return
			}

			// Close and get response
			resp, err := stream.CloseAndRecv()
			if err != nil {
				resChan <- result{"", err}
				return
			}

			resChan <- result{resp.VideoUrl, nil}
		}(fh)
	}


	var uploaded []string
	for i := 0; i < len(files); i++ {
		res := <-resChan
		if res.Err != nil {
			fmt.Printf("Upload failed: %v\n", res.Err)
			continue
		}
		uploaded = append(uploaded, res.URL)
	}

	fmt.Fprintf(w, "Uploaded videos: %v", uploaded)
}
