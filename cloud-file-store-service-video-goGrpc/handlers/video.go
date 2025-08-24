package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	pb "github.com/grpc/video"
	"github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/types/known/timestamppb"
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

	req, err := stream.Recv()
	if err != nil {
		return err
	}
	userID := req.UserId
	originalFilename := req.OriginalFilename

	key := fmt.Sprintf("video/%s-%s-%s", userID, time.Now().Format("20060102-150405"), originalFilename)

	go func() {
		fmt.Println("uploading")
		_, err := s.S3Uploader.Upload(context.Background(), &s3.PutObjectInput{
			Bucket: &s.S3Bucket,
			Key:    aws.String(key),
			Body:   pr,
		})
		if err != nil {
			fmt.Println(err)
			uploadDone <- err
		} else {
			uploadDone <- nil
		}
	}()

	if len(req.ChunkData) > 0 {
		if _, err := pw.Write(req.ChunkData); err != nil {
			pw.CloseWithError(err)
			return err
		}
	}

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

		if req.IsLastChunk {
			break
		}
	}

	pw.Close()

	if err := <-uploadDone; err != nil {
		return err
	}

	region := os.Getenv("AWS_REGION")

	url := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", s.S3Bucket, region, key)

	id, err := s.SaveToDB(userID, key, originalFilename, req.MimeType, req.FileSize, url)

	fmt.Println(err)
	if err != nil {
		return stream.SendAndClose(&pb.UploadVideoResponse{
			Success:      false,
			ErrorMessage: "Internal server error",
		})
	}

	return stream.SendAndClose(&pb.UploadVideoResponse{
		Success:  true,
		VideoUrl: fmt.Sprintf("http://localhost:8080/api/video/watch/%s", id.String()),
	})
}

func (s *Server) SaveToDB(userId string, s3Key, filename, mimeType string, fileSize int64, url string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.DB.QueryRow(`
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

func (s *Server) GetVideo(req *pb.GetVideoRequest, stream pb.VideoService_GetVideoServer) error {
	vid := req.Vid

	fmt.Println("hit")
	s3Key, err := s.GetS3Key(vid)

	if err != nil {
		return fmt.Errorf("video not found: %w", err)
	}

	resp, err := s.S3Client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(s.S3Bucket),
		Key:    aws.String(s3Key),
	})

	if err != nil {
		return fmt.Errorf("failed to get S3 object: %w", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 1024*1024*5)

	for {
		n, err := resp.Body.Read(buf)

		if err != nil && err != io.EOF {
			return fmt.Errorf("error reading S3 object: %w", err)
		}

		if n > 0 {
			if err := stream.Send(&pb.GetVideoResponse{
				ChunkData: buf[:n],
			}); err != nil {

				return fmt.Errorf("failed to send chunk: %w", err)
			}
		}

		if err == io.EOF {
			break
		}
	}

	return nil
}

func (s *Server) GetS3Key(vid string) (string, error) {
	var s3Key string
	err := s.DB.QueryRow(`SELECT s3_key FROM videos WHERE id = $1`, vid).Scan(&s3Key)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("video not found")
		}
		return "", fmt.Errorf("internal server error: %w", err)
	}
	return s3Key, nil
}

func (s *Server) DeleteVideo(ctx context.Context, req *pb.DeleteVideoRequest) (*pb.DeleteVideoResponse, error) {
	vid := req.Vid
	userID := req.UserID

	err := s.DeleteFromDB(vid, userID)

	if err != nil {
		return &pb.DeleteVideoResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &pb.DeleteVideoResponse{
		Success: true,
		Message: "video deleted successfully",
	}, nil
}

func (s *Server) UploadVideoFromThirdParty(stream pb.VideoService_UploadVideoFromThirdPartyServer) error {
	fmt.Println("hit grpc")
	pr, pw := io.Pipe()
	defer pr.Close()

	req, err := stream.Recv()

	if err != nil {
		return err
	}

	userID := req.UserId
	originalFilename := req.OriginalFilename

	errorChn := make(chan error, 1)

	key := fmt.Sprintf("video/%s-%s-%s", userID, time.Now().Format("20060102-150405"), originalFilename)

	go func() {

		_, err := s.S3Uploader.Upload(context.Background(), &s3.PutObjectInput{
			Bucket: &s.S3Bucket,
			Key:    aws.String(key),
			Body:   pr,
		})

		if err != nil {
			errorChn <- err
		} else {
			errorChn <- nil
		}

	}()

	if len(req.ChunkData) > 0 {
		if _, err := pw.Write(req.ChunkData); err != nil {
			pw.CloseWithError(err)
			return err
		}
	}

	for {
		req, err := stream.Recv()

		if err == io.EOF {
			break
		}

		if err != nil {
			pw.CloseWithError(err)
			return err
		}

		if _, err := pw.Write(req.ChunkData); err != nil {
			pw.CloseWithError(err)
			return err
		}

		if req.IsLastChunk {
			break
		}
	}

	pw.Close()

	if err := <-errorChn; err != nil {
		return stream.SendAndClose(&pb.UploadVideoFromThirdPartyResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("S3 upload failed: %v", err),
		})
	}

	region := os.Getenv("AWS_REGION")

	url := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", s.S3Bucket, region, key)

	id, err := s.SaveToDB(userID, key, originalFilename, req.MimeType, req.FileSize, url)

	fmt.Println(err)
	if err != nil {
		return stream.SendAndClose(&pb.UploadVideoFromThirdPartyResponse{
			Success:      false,
			ErrorMessage: "Internal server error",
		})
	}

	return stream.SendAndClose(&pb.UploadVideoFromThirdPartyResponse{
		Success:  true,
		VideoUrl: fmt.Sprintf("http://localhost:8080/api/video/watch/?vid=%s", id.String()),
	})

}

func (s *Server) DeleteVideoFromThirdParty(ctx context.Context, req *pb.DeleteVideoFromThirdPartyRequest) (*pb.DeleteVideoFromThirdPartyResponse, error) {

	vid := req.Vid
	userID := req.UserId

	err := s.DeleteFromDB(vid, userID)

	if err != nil {
		return &pb.DeleteVideoFromThirdPartyResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &pb.DeleteVideoFromThirdPartyResponse{
		Success: true,
		Message: "video deleted successfully",
	}, nil
}

func (s *Server) DeleteFromDB(vid string, userID string) error {
	res, err := s.DB.Exec(`DELETE FROM videos WHERE id = $1 AND user_id = $2`, vid, userID)

	if err != nil {
		return fmt.Errorf("failed to delete video: %v", err)
	}

	count, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %v", err)
	}

	if count == 0 {
		return fmt.Errorf("no video found with this ID for the user")
	}

	return nil
}

func (s *Server) GetAllVideosWithUserID(ctx context.Context, req *pb.GetAllVideosWithUserIDRequest) (*pb.GetAllVideosWithUserIDResponse, error) {
    userId := req.UserId

    rows, err := s.DB.QueryContext(ctx, `
        SELECT id, original_filename, mime_type, file_size_bytes, url, upload_date
        FROM videos
        WHERE user_id = $1
    `, userId)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var videos []*pb.VideoMetadata

    for rows.Next() {
        var (
            id, filename, mimeType, url string
            fileSize int64
            uploadDate time.Time
        )

        if err := rows.Scan(&id, &filename, &mimeType, &fileSize, &url, &uploadDate); err != nil {
            return nil, err
        }

        videos = append(videos, &pb.VideoMetadata{
            Vid:              id,
            OriginalFilename: filename,
            MimeType:         mimeType,
            FileSizeBytes:    fileSize,
            Url:              url,
            UploadDate:       timestamppb.New(uploadDate),
        })
    }

    if err := rows.Err(); err != nil {
        return nil, err
    }

    return &pb.GetAllVideosWithUserIDResponse{Videos: videos}, nil
}

