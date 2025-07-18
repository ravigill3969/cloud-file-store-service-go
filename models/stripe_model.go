package models

import "time"

type CancelSubscriptionStripe struct {
	CustomerId            string
	SubscriptionId        string
	SubscriptionStartDate time.Time
}


//   subscription_status TEXT,         -- 'active', 'canceled', 'past_due', etc.