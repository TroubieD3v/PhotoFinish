// Package clock provides Unix nanosecond timestamps with sub-microsecond
// resolution on every platform PhotoFinish supports.
package clock

import "time"

// Race evidence (the demo's X-Arrival-Ns header, the engines' send and
// receive timestamps) is about how close together requests travel, so it needs
// sub-microsecond resolution.
// time.Now().UnixNano() does not give that everywhere: on Windows the wall
// clock and Go's monotonic clock advance in steps of tens of microseconds and,
// under load, about half a millisecond, which collapses a single-packet burst
// into one value. UnixNano therefore reads a high-resolution tick counter
// (see clock_windows.go and clock_other.go) and anchors it to the wall clock
// once, so the values stay Unix nanoseconds that sort and subtract correctly.

var (
	anchorWall  = time.Now().UnixNano()
	anchorTicks = ticks()
)

// UnixNano returns the current time in Unix nanoseconds with the
// resolution of the platform's high-resolution counter.
func UnixNano() int64 {
	return anchorWall + ticksToNanos(ticks()-anchorTicks)
}
