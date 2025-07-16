package handlers

import (
	"database/sql"
	"net/http"
	"os"

	"github.com/ravigill3969/cloud-file-store/utils"
	"github.com/redis/go-redis/v9"
	"github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/checkout/session"
)

type Stripe struct {
	Db          *sql.DB
	RedisClient *redis.Client
}

func CreateCheckoutSession(w http.ResponseWriter, r *http.Request) {
	stripe.Key = os.Getenv("STRIPE_KEY")
	priceId := os.Getenv("STRIPE_PRICE_ID")

	params := &stripe.CheckoutSessionParams{
		SuccessURL: stripe.String("https://example.com/success"),
		CancelURL:  stripe.String("https://example.com/cancel"),
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
