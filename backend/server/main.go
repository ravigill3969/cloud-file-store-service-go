package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/joho/godotenv"
	"github.com/ravigill3969/cloud-file-store/backend/database"
	"github.com/ravigill3969/cloud-file-store/backend/handlers"
	middleware "github.com/ravigill3969/cloud-file-store/backend/middlewares"
	"github.com/ravigill3969/cloud-file-store/backend/routes"
	"github.com/ravigill3969/cloud-file-store/backend/utils"
	"github.com/redis/go-redis/v9"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file: %s", err)
	}

	db, err := database.ConnectDB()

	if err != nil {
		log.Fatalf("Database connection failed: %v", err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			log.Printf("Error closing database connection: %v", closeErr)
		}
		fmt.Println("Database connection closed.")
	}()

	redisURL := os.Getenv("UPSTASH_REDIS_URL")
	if redisURL == "" {
		log.Fatal("UPSTASH_REDIS_URL is required")
	}

	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Fatalf("Invalid Upstash Redis URL: %v", err)
	}

	redisClient := redis.NewClient(opt)

	PORT := os.Getenv("PORT")
	if PORT == "" {
		PORT = "8080"
	}

	region := os.Getenv("AWS_REGION")

	if region == "" {
		fmt.Println("region is required")
		return
	}
	bucket := os.Getenv("AWS_BUCKET_NAME")

	if bucket == " " {
		fmt.Println("bucket is required")
		return
	}

	backend_url := os.Getenv("BACKEND_URL")

	if backend_url == " " {
		fmt.Println("backend_url is required")
		return
	}

	accessKey := os.Getenv("AWS_S3_BUCKET_ACCESS_KEY")
	secretKey := os.Getenv("AWS_S3_BUCKET_SECRET_ACCESS_KEY")
	// domainAWSCloudfront := os.Getenv("AWS_CLOUDFRONT_DOMAIN")

	if accessKey == "" || secretKey == "" {
		log.Fatal("AWS credentials are required")
	}

	sess := session.Must(session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewStaticCredentials(accessKey, secretKey, ""),
	}))

	s3Uploader := s3manager.NewUploader(sess)
	s3Client := s3.New(sess)

	mux := http.NewServeMux()

	userHandler := &handlers.UserHandler{
		DB:          db,
		RedisClient: redisClient,
	}
	fileHandler := &handlers.FileHandler{
		DB:                  db,
		S3Uploader:          s3Uploader,
		S3Client:            s3Client,
		S3Bucket:            bucket,
		Redis:               redisClient,
		AWSCloudFrontDomain: "water",
		BACKEND_URL : backend_url,
	}
	stripeHandler := &handlers.Stripe{
		Db: db,
	}

	go func() {
		for {
			utils.CleanupDeletedImages(context.Background(), db, s3Client, bucket)
			time.Sleep(24 * time.Hour)
		}
	}()

	mux.HandleFunc("/webhook", stripeHandler.HandleWebhook)
	routes.RegisterUserRoutes(mux, userHandler, redisClient)
	routes.FileRoutes(mux, fileHandler, redisClient)
	routes.StripeRoutes(mux, stripeHandler, redisClient)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		utils.RespondError(w, http.StatusBadGateway, "This route donot exist")
	})

	middleware := middleware.CORS(
		middleware.SetCommonHeaders(
			middleware.GlobalRateLimiter(redisClient)(mux),
		),
	)

	fmt.Printf("server is running on http://localhost:%s\n", PORT)

	log.Fatal(http.ListenAndServe(":"+PORT, middleware))
}
