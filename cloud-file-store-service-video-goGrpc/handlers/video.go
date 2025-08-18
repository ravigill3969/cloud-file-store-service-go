package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	pb "github.com/grpc/video"
	"github.com/redis/go-redis/v9"
)

type Server struct {
	pb.UnimplementedVideoServiceServer
	DB         *sql.DB
	S3Uploader *manager.Uploader
	S3Client   *s3.Client
	S3Bucket   string
	Redis      *redis.Client
}

func (s *Server) UploadVideo(stream pb.VideoService_UploadVideoServer) error {
	pr, pw := io.Pipe()
	defer pr.Close()
	uploadDone := make(chan error, 1)

	// Receive first chunk to get metadata
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	userID := req.UserId
	originalFilename := req.OriginalFilename

	key := fmt.Sprintf("video/%s-%s-%s", userID, time.Now().Format("20060102-150405"), originalFilename)

	go func() {
		_, err := s.S3Uploader.Upload(context.Background(), &s3.PutObjectInput{
			Bucket: &s.S3Bucket,
			Key:    aws.String(key),
			Body:   pr,
		})
		uploadDone <- err
	}()

	// Write first chunk
	if len(req.ChunkData) > 0 {
		if _, err := pw.Write(req.ChunkData); err != nil {
			return err
		}
	}

	// Continue receiving chunks
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if len(req.ChunkData) > 0 {
			if _, err := pw.Write(req.ChunkData); err != nil {
				return err
			}
		}
	}

	pw.Close()

	if err := <-uploadDone; err != nil {
		return err
	}

	return stream.SendAndClose(&pb.UploadVideoResponse{
		Success:  true,
		VideoUrl: fmt.Sprintf("https://%s.s3.amazonaws.com/%s", s.S3Bucket, key),
	})
}
