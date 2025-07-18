package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	middleware "github.com/ravigill3969/cloud-file-store/middlewares"
	"github.com/ravigill3969/cloud-file-store/utils"
	"github.com/redis/go-redis/v9"
	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/checkout/session"
)

type Stripe struct {
	Db    *sql.DB
	Redis *redis.Client
}

type metadataKey string

const MetadataUserID metadataKey = "userID"

func (s *Stripe) CreateCheckoutSession(w http.ResponseWriter, r *http.Request) {
	stripe.Key = os.Getenv("STRIPE_KEY")
	priceId := os.Getenv("STRIPE_PRICE_ID")

	userID, ok := r.Context().Value(middleware.UserIDContextKey).(string)

	if !ok {
		log.Printf("Error: User ID not found in context")
		http.Error(w, "Unauthorized: User ID not provided", http.StatusUnauthorized)
		return
	}

	fmt.Println(userID)

	params := &stripe.CheckoutSessionParams{
		SuccessURL: stripe.String("http://localhost:5173/success?session_id={CHECKOUT_SESSION_ID}"),
		CancelURL:  stripe.String("http://localhost:5173/cancel"),
		Mode:       stripe.String(string(stripe.CheckoutSessionModeSubscription)),

		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(priceId),
				Quantity: stripe.Int64(1),
			},
		},
		SubscriptionData: &stripe.CheckoutSessionSubscriptionDataParams{
			Metadata: map[string]string{
				"userID": userID,
			},
		},
	}

	params.AddMetadata("userID", userID)

	result, err := session.New(params)

	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	url := result.URL

	utils.SendJSON(w, http.StatusOK, url)
}

func (s *Stripe) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	const MaxBodyBytes = int64(65536)
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading request body: %v\n", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	event := stripe.Event{}

	if err := json.Unmarshal(payload, &event); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse webhook body json: %v\n", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	switch event.Type {
	case "checkout.session.completed":

		err = utils.HandlePaymentSessionCompleted(s.Db, event)

		fmt.Println("created session completed")

		if err != nil {
			utils.SendError(w, http.StatusInternalServerError, err.Error())
			return
		}

		return
	case "invoice.paid":
		err := utils.HandleInvoicePaid(s.Db, event)

		fmt.Println("invoice paid")

		if err != nil {
			utils.SendError(w, http.StatusInternalServerError, "Payment failed")
			return
		}

		return
	default:
		log.Printf("Unhandled event type: %s", event.Type)
	}

	w.WriteHeader(http.StatusOK)
}
