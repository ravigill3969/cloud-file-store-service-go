package utils

import (
	"fmt"
	"os"

	"github.com/redis/go-redis/v9"
)

func InitRedis() (*redis.Client, error) {
	redisURL := os.Getenv("UPSTASH_REDIS_URL")
	if redisURL == "" {
		return nil, fmt.Errorf("UPSTASH_REDIS_URL is required")
	}

	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("Invalid Upstash Redis URL: %w", err)
	}

	return redis.NewClient(opt), nil
}
