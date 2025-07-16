package routes

import (
	"net/http"

	"github.com/ravigill3969/cloud-file-store/handlers"
)

func StripeRouter(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/stripe/create-session", handlers.CreateCheckoutSession)
}
