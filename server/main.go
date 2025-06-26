package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/ravigill3969/cloud-file-store/database"
	"github.com/ravigill3969/cloud-file-store/handlers"
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

	PORT := os.Getenv("PORT")
	if PORT == "" {
		PORT = "8080"
	}

	mux := http.NewServeMux()

	userHandler := &handlers.UserHandler{DB: db}

	routes.RegisterUserRoutes(mux, userHandler)

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, Go HTTP server! Your routes are ready and database is connected.")
	})

	fmt.Printf("TLS server is running on http://localhost:%s\n", PORT)

	log.Fatal(http.ListenAndServeTLS(":"+PORT, "cert.pem", "key.pem", mux))
}	
