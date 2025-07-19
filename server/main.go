package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"

	"github.com/ravigill3969/cloud-file-store/database"
	"github.com/ravigill3969/cloud-file-store/handlers"
	middleware "github.com/ravigill3969/cloud-file-store/middlewares"
	"github.com/ravigill3969/cloud-file-store/routes"
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

	if bucket == "" {
		fmt.Println("bucket is required")
		return
	}

	accessKey := os.Getenv("AWS_S3_BUCKET_ACCESS_KEY")
	secretKey := os.Getenv("AWS_S3_BUCKET_SECRET_ACCESS_KEY")

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
		DB:         db,
		S3Uploader: s3Uploader,
		S3Client:   s3Client,
		S3Bucket:   bucket,
		Redis:      redisClient,
	}
	stripeHandler := &handlers.Stripe{
		Db: db,
	}

	mux.HandleFunc("/webhook", stripeHandler.HandleWebhook)
	routes.RegisterUserRoutes(mux, userHandler, redisClient)
	routes.FileRoutes(mux, fileHandler, redisClient)
	routes.StripeRoutes(mux, stripeHandler, redisClient)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, Go HTTP server! Your routes are ready and database is connected.")
	})

	middleware := middleware.CORS(middleware.SetCommonHeaders(mux))

	fmt.Printf("server is running on http://localhost:%s\n", PORT)

	log.Fatal(http.ListenAndServe(":"+PORT, middleware))
}
