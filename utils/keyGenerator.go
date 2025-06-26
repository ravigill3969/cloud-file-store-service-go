package utils

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
)

func GenerateKey(length int) (string, error) {
	if length <= 0 {
		return "", errors.New("length must be a positive integer")
	}

	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}
