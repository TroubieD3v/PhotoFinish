package demo

import "time"

// The X-Arrival-Ns header is the server-side evidence of how close together
// the requests of one race arrived, so it needs sub-microsecond resolution.
// time.Now().UnixNano() does not give that everywhere: on Windows the wall
// clock and Go's monotonic clock advance in steps of tens of microseconds and,
// under load, about half a millisecond, which collapses a single-packet burst
// into one value. arrivalNanos therefore reads a high-resolution tick counter
// (see clock_windows.go and clock_other.go) and anchors it to the wall clock
// once, so the values stay Unix nanoseconds that sort and subtract correctly.

var (
	anchorWall  = time.Now().UnixNano()
	anchorTicks = ticks()
)

// arrivalNanos returns the current time in Unix nanoseconds with the
// resolution of the platform's high-resolution counter.
func arrivalNanos() int64 {
	return anchorWall + ticksToNanos(ticks()-anchorTicks)
}
