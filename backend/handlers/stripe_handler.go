package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	middleware "github.com/ravigill3969/cloud-file-store/backend/middlewares"
	"github.com/ravigill3969/cloud-file-store/backend/models"
	"github.com/ravigill3969/cloud-file-store/backend/utils"
	"github.com/redis/go-redis/v9"
	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/checkout/session"
	"github.com/stripe/stripe-go/v82/subscription"
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
		utils.RespondError(w, http.StatusUnauthorized, "Unauthorized: User ID not provided")
		return
	}

	var CustomerId string

	s.Db.QueryRow(`SELECT stripe_customer_id FROM stripe WHERE user_id = $1`, userID).Scan(&CustomerId)

	params := &stripe.CheckoutSessionParams{
		SuccessURL: stripe.String("http://localhost:5173/success"),
		CancelURL:  stripe.String("http://localhost:5173/cancel"),
		Mode:       stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		// Customer:   stripe.String(string(CustomerId)),

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

	if CustomerId != "" {
		params.Customer = &CustomerId
	}

	params.AddMetadata("userID", userID)

	result, err := session.New(params)

	if err != nil {
		utils.RespondInternal(w, err, "Unable to create checkout session")
		return
	}

	url := result.URL

	utils.RespondSuccess(w, http.StatusOK, map[string]string{"checkout_url": url})
}

func (s *Stripe) CancelSubscription(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.UserIDContextKey).(string)

	if !ok {
		utils.RespondError(w, http.StatusUnauthorized, "Unauthorized: User ID not provided")
		return
	}

	var user models.CancelSubscriptionStripe

	err := s.Db.QueryRow(`SELECT stripe_customer_id, stripe_subscription_id, current_period_start from stripe WHERE user_id = $1`, userID).Scan(&user.CustomerId, &user.SubscriptionId, &user.SubscriptionCurrentPeriodStart)

	if err != nil {

		if err == sql.ErrNoRows {
			utils.RespondError(w, http.StatusNotFound, "Subscription not found")

		} else {
			utils.RespondInternal(w, err, "Failed to fetch subscription")
		}
		return
	}

	stripe.Key = os.Getenv("STRIPE_KEY")

	params := &stripe.SubscriptionParams{CancelAtPeriodEnd: stripe.Bool(true)}

	_, err = subscription.Update(user.SubscriptionId, params)

	if err != nil {
		utils.RespondInternal(w, err, "Failed to set subscription cancel at period end")
		return
	}

	_, err = s.Db.Exec(`UPDATE users SET account_type = 'cancel_at_period_end' WHERE uuid = $1`, userID)

	if err != nil {
		fmt.Println(err)

		if err == sql.ErrNoRows {
			utils.RespondInternal(w, err, "Unable to update subscription status")

		} else {
			utils.RespondInternal(w, err, "Failed to update subscription")
		}
		return
	}

	utils.RespondSuccess(w, http.StatusOK, map[string]string{"status": "cancel_at_period_end"})

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
		fmt.Println("session compledeted")
		err = utils.HandlePaymentSessionCompleted(s.Db, event)
		fmt.Println("created session completed")
		if err != nil {
			utils.RespondInternal(w, err, "Failed to mark session complete")
			return
		}
		return

	case "invoice.paid":
		err = utils.HandleInvoicePaid(s.Db, event)
		fmt.Println("invoice paid")
		if err != nil {
			utils.RespondInternal(w, err, "Payment failed")
			return
		}
		return

	case "invoice.payment_failed":
		fmt.Println("payment failed")
		return

	case "customer.subscription.updated":

		err := utils.HandleSubscriptionUpdated(s.Db, event)

		if err != nil {
			utils.RespondInternal(w, err, "Unable to update subscription")
			return
		}

		return

	case "customer.subscription.deleted":

		fmt.Println("I am also called")
		err := utils.HandleSubscriptionDeleted(s.Db, event)

		if err != nil {
			utils.RespondInternal(w, err, "Unable to cancel subscription")
			return
		}

		return

	default:
		log.Printf("Unhandled event type: %s", event.Type)
	}

	w.WriteHeader(http.StatusOK)
}
