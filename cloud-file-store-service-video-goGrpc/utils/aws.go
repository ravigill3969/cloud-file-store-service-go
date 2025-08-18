package utils

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func InitAWS() (*s3.Client, *manager.Uploader, string, error) {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		return nil, nil, "", fmt.Errorf("AWS_REGION is required")
	}

	bucket := os.Getenv("AWS_BUCKET_NAME")
	if bucket == "" {
		return nil, nil, "", fmt.Errorf("AWS_BUCKET_NAME is required")
	}

	accessKey := os.Getenv("AWS_S3_BUCKET_ACCESS_KEY")
	secretKey := os.Getenv("AWS_S3_BUCKET_SECRET_ACCESS_KEY")
	if accessKey == "" || secretKey == "" {
		return nil, nil, "", fmt.Errorf("AWS credentials are required")
	}

	cfg, err := config.LoadDefaultConfig(
		context.Background(),
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)
	if err != nil {
		return nil, nil, "", fmt.Errorf("Unable to load AWS config: %w", err)
	}

	s3Client := s3.NewFromConfig(cfg)
	s3Uploader := manager.NewUploader(s3Client)

	return s3Client, s3Uploader, bucket, nil
}
