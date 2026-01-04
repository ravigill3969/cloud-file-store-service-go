package models

import "time"

type CancelSubscriptionStripe struct {
	CustomerId                     string
	SubscriptionId                 string
	SubscriptionCurrentPeriodStart time.Time
}

//   subscription_status TEXT,         -- 'active', 'canceled', 'past_due', etc.
