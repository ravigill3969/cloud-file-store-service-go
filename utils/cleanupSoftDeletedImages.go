package utils

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"
)

func CleanupSoftDeletedImages(db *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := db.ExecContext(ctx, `
		DELETE FROM images
		WHERE deleted = TRUE AND deleted_at < NOW() - INTERVAL '7 days'
	`)
	if err != nil {
		fmt.Printf("Something went wrong %s", err.Error())
	}

	rowsDeleted, err := result.RowsAffected()
	if err != nil {
		fmt.Printf("Something went wrong %s", err.Error())
	}

	log.Printf("Cleanup: deleted %d soft-deleted images older than 7 days", rowsDeleted)
	return nil
}
