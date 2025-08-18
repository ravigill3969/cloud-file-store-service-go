package main

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/joho/godotenv"

	"github.com/grpc/database"
	"github.com/grpc/handlers"
	"github.com/grpc/utils"
	pb "github.com/grpc/video"
	"google.golang.org/grpc"
)

// -------------------- DB --------------------
func initDB() (*sql.DB, error) {
	db, err := database.ConnectDB()
	if err != nil {
		return nil, fmt.Errorf("Database connection failed: %w", err)
	}
	return db, nil
}

// -------------------- Main --------------------
func main() {
	if err := godotenv.Load(".env"); err != nil {
		log.Fatalf("Error loading .env file: %s", err)
	}

	db, err := initDB()
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			log.Printf("Error closing database connection: %v", closeErr)
		}
		fmt.Println("Database connection closed.")
	}()

	s3Client, s3Uploader, bucket, err := utils.InitAWS()
	if err != nil {
		log.Fatal(err)
	}

	redisClient, err := utils.InitRedis()
	if err != nil {
		log.Fatal(err)
	}

	PORT := os.Getenv("PORT")
	if PORT == "" {
		PORT = ":50051"
	}

	lis, err := net.Listen("tcp", PORT)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	server := &handlers.Server{
		DB:         db,
		S3Uploader: s3Uploader,
		S3Client:   s3Client,
		S3Bucket:   bucket,
		Redis:      redisClient,
	}

	s := grpc.NewServer()
	pb.RegisterVideoServiceServer(s, server)

	log.Println("gRPC server running on", PORT)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
