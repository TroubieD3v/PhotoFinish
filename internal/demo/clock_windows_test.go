//go:build windows

package demo

import (
	"testing"
	"time"
)

// TestTicksToNanosNoOverflow converts 30 days of counter ticks: a naive
// d*1e9/f would overflow int64 long before that.
func TestTicksToNanosNoOverflow(t *testing.T) {
	month := 30 * 24 * time.Hour
	d := int64(month/time.Second) * counterFrequency
	if got := ticksToNanos(d); got != int64(month) {
		t.Fatalf("ticksToNanos(30 days) = %d, want %d", got, int64(month))
	}
	if got := ticksToNanos(counterFrequency + 1); got <= int64(time.Second) {
		t.Fatalf("sub-second remainder lost: %d", got)
	}
}
