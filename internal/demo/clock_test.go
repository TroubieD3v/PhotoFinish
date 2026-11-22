package demo

import (
	"testing"
	"time"
)

// TestArrivalClockResolution guards the reason arrivalNanos exists: two reads
// a few microseconds apart must differ. A clock that only advances every tens
// of microseconds (the Windows wall clock) fails this test.
func TestArrivalClockResolution(t *testing.T) {
	smallest := int64(1 << 62)
	deadline := time.Now().Add(2 * time.Second)
	for i := 0; i < 200 && time.Now().Before(deadline); i++ {
		a := arrivalNanos()
		b := arrivalNanos()
		for b == a {
			b = arrivalNanos()
		}
		if d := b - a; d < smallest {
			smallest = d
		}
	}
	if smallest > 5_000 {
		t.Fatalf("arrival clock resolution is %dns, want at most 5µs", smallest)
	}
}

// TestArrivalClockTracksWallClock checks that values stay Unix nanoseconds:
// close to time.Now and never going backwards.
func TestArrivalClockTracksWallClock(t *testing.T) {
	if diff := arrivalNanos() - time.Now().UnixNano(); diff > int64(50*time.Millisecond) || diff < -int64(50*time.Millisecond) {
		t.Fatalf("arrival clock is %s away from the wall clock", time.Duration(diff))
	}
	prev := arrivalNanos()
	for i := 0; i < 10000; i++ {
		now := arrivalNanos()
		if now < prev {
			t.Fatalf("arrival clock went backwards: %d after %d", now, prev)
		}
		prev = now
	}
}
