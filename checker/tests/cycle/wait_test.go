package cycle_test

import (
	"context"
	"testing"
	"time"

	"proxies-checker/internal/cycle"
)

func TestWaitForNextCycleReturnsFalseOnCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	start := time.Now()
	if cycle.WaitForNextCycle(ctx, time.Second) {
		t.Fatal("expected cancellation to stop the wait")
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("expected prompt cancellation, waited %v", elapsed)
	}
}

func TestWaitForNextCycleReturnsTrueAfterDelay(t *testing.T) {
	t.Parallel()

	if !cycle.WaitForNextCycle(t.Context(), 10*time.Millisecond) {
		t.Fatal("expected wait to complete when context stays active")
	}
}
