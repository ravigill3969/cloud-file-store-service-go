package models

import "time"

type CancelSubscriptionStripe struct {
	CustomerId            string
	SubscriptionId        string
	SubscriptionStartDate time.Time
}
