

package cloudfilestoreservicego


func (s *Stripe) VerifyCheckoutSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	sess, err := session.Get(req.SessionID, nil)

	// userData := sess.Metadata["userID"]

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
        account_type = 'basic',
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