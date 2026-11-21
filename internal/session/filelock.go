package session

import (
	"context"
	"os"
	"time"
)

// LockFileContext waits to acquire a file lock or for ctx to be canceled.
func LockFileContext(ctx context.Context, file *os.File, exclusive bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := LockFile(file, exclusive)
	if !lockContended(err) {
		return err
	}
	retry := time.NewTicker(20 * time.Millisecond)
	defer retry.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-retry.C:
			if err := ctx.Err(); err != nil {
				return err
			}
			err := LockFile(file, exclusive)
			if !lockContended(err) {
				return err
			}
		}
	}
}
