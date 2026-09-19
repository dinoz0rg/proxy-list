package cycle

import (
	"context"
	"time"
)

// WaitForNextCycle waits for the requested delay or returns early on cancellation.
func WaitForNextCycle(ctx context.Context, sleep time.Duration) bool {
	timer := time.NewTimer(sleep)
	defer timer.Stop()

	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
