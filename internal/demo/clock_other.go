//go:build !windows

package demo

import "time"

// monotonicBase is the reference point for Go's monotonic clock, which has
// nanosecond resolution on Linux and macOS.
var monotonicBase = time.Now()

// ticks returns nanoseconds of the monotonic clock since monotonicBase.
func ticks() int64 {
	return int64(time.Since(monotonicBase))
}

// ticksToNanos is the identity: ticks are already nanoseconds.
func ticksToNanos(d int64) int64 {
	return d
}
