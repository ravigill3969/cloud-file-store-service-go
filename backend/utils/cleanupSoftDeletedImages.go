package utils

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
)

func CleanupDeletedImages(ctx context.Context, db *sql.DB, s3Client *s3.S3, bucket string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, `
	DELETE FROM images
	WHERE deleted = TRUE AND deleted_at < NOW() - INTERVAL '7 days'
	RETURNING s3_key

	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var s3Keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return err
		}
		s3Keys = append(s3Keys, key)
	}

	if len(s3Keys) == 0 {
		log.Println("No images to delete from S3")
		return nil
	}

	for _, key := range s3Keys {
		_, err := s3Client.DeleteObject(&s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		if err != nil {
			log.Printf("Failed to delete S3 object %s: %v", key, err)
		} else {
			log.Printf("Deleted S3 object %s", key)
		}
	}

	return nil
}
