package utils

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/stripe/stripe-go/v82"
)

func HandleInvoicePaid(db *sql.DB, event stripe.Event) error {

	var inv stripe.Invoice

	if err := json.Unmarshal(event.Data.Raw, &inv); err != nil {
		return fmt.Errorf("failed to parse invoice.payment_succeeded: %w", err)
	}

	// pretty, err := json.MarshalIndent(inv, "", "  ")
	// if err != nil {
	// 	log.Println("Failed to marshal invoice for logging:", err)
	// } else {
	// 	log.Println("Parsed Stripe Invoice:\n", string(pretty))
	// }

	periodStart := time.Unix(inv.PeriodStart, 0)
	periodEnd := time.Unix(inv.PeriodEnd, 0)

	// customerId := inv.Customer.ID
	userID := inv.Parent.SubscriptionDetails.Metadata["userID"]

	stripe.Key = os.Getenv("STRIPE_KEY")

	priceID := os.Getenv("STRIPE_PRICE_ID")

	fmt.Println("price", priceID)
	//todo - update account_Type = standard
	_, err := db.Exec(`
	UPDATE users
	SET post_api_calls = 500,
	get_api_calls = 500,
	edit_api_calls = 50,
	account_type = 'basic' 
	WHERE uuid = $1
	`, userID)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)

	}

	_, err = db.Exec(`
	UPDATE stripe
	SET subscription_status = 'active',
	current_period_start = $1,
	current_period_end = $2,
	cancel_at_period_end = $3,
	price_id = $4,
	updated_at = now()
	WHERE user_id = $5
	`,
		periodStart, periodEnd, true, priceID, userID)
	if err != nil {
		return fmt.Errorf("failed to update stripe record: %w", err)

	}
	return nil
}

func HandlePaymentSessionCompleted(db *sql.DB, event stripe.Event) error {
	fmt.Println("createting session")

	var session stripe.CheckoutSession
	err := json.Unmarshal(event.Data.Raw, &session)
	if err != nil {
		return fmt.Errorf("something went wrong")

	}
	userID := session.Metadata[string("userID")]
	priceId := os.Getenv("STRIPE_PRICE_ID")
	subscriptionID := session.Subscription.ID
	customerID := session.Customer.ID
	_, err = db.Exec(`
		INSERT INTO stripe (user_id, stripe_customer_id, stripe_subscription_id, price_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id)
		DO UPDATE SET
			stripe_customer_id = EXCLUDED.stripe_customer_id,
			stripe_subscription_id = EXCLUDED.stripe_subscription_id,
			price_id = EXCLUDED.price_id,
			updated_at = now()
	`, userID, customerID, subscriptionID, priceId)

	return err
}

func HandleSubscriptionUpdated(db *sql.DB, event stripe.Event) error {
	fmt.Print("subscritpion updated paid")

	var inv stripe.Invoice

	if err := json.Unmarshal(event.Data.Raw, &inv); err != nil {
		return fmt.Errorf("failed to parse invoice.payment_succeeded: %w", err)
	}

	// // Optional: Pretty log the invoice
	// if pretty, err := json.MarshalIndent(inv, "", "  "); err == nil {
	// 	log.Println("Parsed Stripe Invoice:\n", string(pretty))
	// }

	userID := inv.Metadata["userID"]
	subscriptionID := inv.ID

	// Begin transaction
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin DB transaction: %w", err)
	}

	defer func() {
		if err != nil {
			_ = tx.Rollback()
		} else {
			_ = tx.Commit()
		}
	}()

	_, err = tx.Exec(`
	UPDATE users
	SET account_type = 'basic'
	WHERE uuid = $1
`, userID)
	if err != nil {
		fmt.Print(err)
		return fmt.Errorf("failed to downgrade user: %w", err)
	}

	// 2. Update Stripe subscription status
	_, err = tx.Exec(`
	UPDATE stripe
	SET subscription_status = 'canceled',
		cancel_at_period_end = true,
		updated_at = now()
	WHERE stripe_subscription_id = $1
`, subscriptionID)
	if err != nil {
		return fmt.Errorf("failed to update stripe record: %w", err)
	}

	log.Println("Subscription canceled and user downgraded successfully.")
	return nil

}
