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

	periodStart := time.Unix(inv.PeriodStart, 0)
	periodEnd := time.Unix(inv.PeriodEnd, 0)

	// Get userID from invoice lines metadata (subscription metadata)
	var userID string
	if inv.Lines != nil && len(inv.Lines.Data) > 0 {
		for _, line := range inv.Lines.Data {
			if line.Metadata != nil {
				if uid, ok := line.Metadata["userID"]; ok {
					userID = uid
					break
				}
			}
		}
	}

	if userID == "" {
		return fmt.Errorf("userID not found in invoice line metadata")
	}

	stripe.Key = os.Getenv("STRIPE_KEY")

	priceID := os.Getenv("STRIPE_PRICE_ID")

	fmt.Println("price", priceID)
	//todo - update account_Type = standard
	_, err := db.Exec(`
	UPDATE users
	SET post_api_calls = 10,
	get_api_calls = 10,
	edit_api_calls = 10,
	account_type = 'standard' 
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
	price_id = $4
	WHERE user_id = $5
	`,
		periodStart, periodEnd, false, priceID, userID)
	if err != nil {
		return fmt.Errorf("failed to update stripe record: %w", err)
	}

	fmt.Println(4)
	log.Printf("Invoice handled for user , customer")
	return nil
}

func HandlePaymentSessionCompleted(db *sql.DB, event stripe.Event) error {
	fmt.Println("createting session")

	var session stripe.CheckoutSession
	err := json.Unmarshal(event.Data.Raw, &session)
	if err != nil {
		return fmt.Errorf("something went wrong")

	}
	userID := session.Metadata["userID"]
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
	var sub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
		return fmt.Errorf("failed to parse subscription.updated: %w", err)
	}

	fmt.Println(string(event.Data.Raw))

	customerID := sub.Customer.ID
	status := string(sub.Status)

	_, err := db.Exec(`
        UPDATE stripe
        SET subscription_status = $1,
		cancel_at_period_end = $2,
		canceled_at = CASE WHEN $2 = true THEN now() ELSE NULL END
        WHERE stripe_customer_id = $3
		`, status, sub.CancelAtPeriodEnd, customerID)

	if err != nil {
		return fmt.Errorf("failed to update stripe record: %w", err)
	}

	return nil
}

func HandleSubscriptionDeleted(db *sql.DB, event stripe.Event) error {
	var sub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
		return fmt.Errorf("failed to parse subscription.deleted: %w", err)
	}

	customerID := sub.Customer.ID
	userID := sub.Metadata["userID"]

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
        UPDATE stripe
        SET subscription_status = 'canceled',
            cancel_at_period_end = false,
            canceled_at = now()
        WHERE stripe_customer_id = $1
    `, customerID)
	if err != nil {
		return fmt.Errorf("failed to update stripe record: %w", err)
	}

	_, err = tx.Exec(`
        UPDATE users
        SET account_type = 'basic',
            post_api_calls = 5,
            get_api_calls = 5,
            edit_api_calls = 5
        WHERE uuid = $1
    `, userID)
	if err != nil {
		return fmt.Errorf("failed to update user record: %w", err)
	}

	return nil
}
