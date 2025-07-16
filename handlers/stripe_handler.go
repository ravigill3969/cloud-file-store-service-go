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
	"github.com/ravigill3969/cloud-file-store/models"
	"github.com/ravigill3969/cloud-file-store/utils"
	"github.com/redis/go-redis/v9"
	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/checkout/session"
	"github.com/stripe/stripe-go/v82/subscription"
	"github.com/stripe/stripe-go/v82/webhook"
)

type Stripe struct {
	Db    *sql.DB
	Redis *redis.Client
}

func (s *Stripe) CreateCheckoutSession(w http.ResponseWriter, r *http.Request) {
	stripe.Key = os.Getenv("STRIPE_KEY")
	priceId := os.Getenv("STRIPE_PRICE_ID")

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
	}

	result, err := session.New(params)
	if err != nil {
		utils.SendError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	url := result.URL

	utils.SendJSON(w, http.StatusOK, url)
}

func (s *Stripe) VerifyCheckoutSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	sess, err := session.Get(req.SessionID, nil)
	if err != nil {
		utils.SendError(w, http.StatusBadRequest, "Invalid session ID")
		return
	}

	if sess.PaymentStatus != stripe.CheckoutSessionPaymentStatusPaid {
		utils.SendError(w, http.StatusBadRequest, "Payment not completed")
		return
	}

	userID, ok := r.Context().Value(middleware.UserIDContextKey).(string)

	if !ok {
		log.Printf("Error: User ID not found in context")
		http.Error(w, "Unauthorized: User ID not provided", http.StatusUnauthorized)
		return
	}

	customerID := sess.Customer.ID
	subscriptionID := sess.Subscription.ID

	_, err = s.Db.Exec(`
    UPDATE users 
    SET post_api_calls = 500,
        get_api_calls = 500,
        edit_api_calls = 50,
        account_type = 'standard',
		stripe_customer_id= $1,
		stripe_subscription_id= $2
    WHERE uuid = $3
`, customerID, subscriptionID, userID)

	fmt.Println(err)
	if err != nil {
		if err == sql.ErrNoRows {
			utils.SendError(w, http.StatusNotFound, "Not found!")
		} else {
			utils.SendError(w, http.StatusInternalServerError, "Internal server error")
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "verified"})
}

func (s *Stripe) CancelSubscription(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.UserIDContextKey).(string)

	if !ok {
		log.Printf("Error: User ID not found in context")
		http.Error(w, "Unauthorized: User ID not provided", http.StatusUnauthorized)
		return
	}

	var user models.CancelSubscriptionStripe

	err := s.Db.QueryRow(`SELECT stripe_customer_id, stripe_subscription_id, subscription_start_date WHERE uuid = $1`, userID).Scan(&user.CustomerId, &user.SubscriptionId, &user.SubscriptionStartDate)

	if err != nil {
		if err == sql.ErrNoRows {
			utils.SendError(w, http.StatusNotFound, "Not found")

		} else {
			utils.SendError(w, http.StatusInternalServerError, "Internal server error")
		}
		return
	}

	params := &stripe.SubscriptionParams{}
	params.CancelAtPeriodEnd = stripe.Bool(true)

	_, err = subscription.Update(user.SubscriptionId, params)

	if err != nil {
		http.Error(w, "Failed to set subscription cancel at period end", http.StatusInternalServerError)
		return
	}

	_, err = s.Db.Exec(`UPDATE users SET account_type = 'cancel_at_period_end' WHERE uuid = $1`)

	if err != nil {
		if err == sql.ErrNoRows {
			utils.SendError(w, http.StatusInternalServerError, "Unable to update")

		} else {
			utils.SendError(w, http.StatusInternalServerError, "Internal server error")
		}
		return
	}

	utils.SendJSON(w, http.StatusOK, "Successfully canceled!")

}

// whsec_7a9713ee0caf4a21c6fe57292dbaef54aa5754d351cea319a244d74608fb939e

func HandleWebhook(w http.ResponseWriter, r *http.Request) {
	const MaxBodyBytes = int64(65536)
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)

	payload, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Request body read error", http.StatusServiceUnavailable)
		return
	}

	endpointSecret := "whsec_7a9713ee0caf4a21c6fe57292dbaef54aa5754d351cea319a244d74608fb939e"
	if endpointSecret == "" {
		http.Error(w, "Webhook secret not configured", http.StatusInternalServerError)
		return
	}

	sigHeader := r.Header.Get("Stripe-Signature")
	event, err := webhook.ConstructEventWithOptions(
		payload,
		sigHeader,
		endpointSecret,
		webhook.ConstructEventOptions{
			IgnoreAPIVersionMismatch: true,
		},
	)

	if err != nil {
		log.Printf("⚠️  Webhook signature verification failed: %v\n", err)
		http.Error(w, "Webhook signature verification failed", http.StatusBadRequest)
		return
	}

	switch event.Type {
	case "payment_intent.succeeded":
		var paymentIntent stripe.PaymentIntent
		err := json.Unmarshal(event.Data.Raw, &paymentIntent)
		if err != nil {
			log.Printf("Error parsing payment intent: %v\n", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		log.Printf("💰 PaymentIntent was successful! ID: %s Amount: %d\n", paymentIntent.ID, paymentIntent.Amount)

	default:
		log.Printf("Unhandled event type: %s\n", event.Type)
	}

	w.WriteHeader(http.StatusOK)
}
