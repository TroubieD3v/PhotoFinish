//go:build windows

package demo

import (
	"syscall"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procQPC          = kernel32.NewProc("QueryPerformanceCounter")
	procQPF          = kernel32.NewProc("QueryPerformanceFrequency")
	counterFrequency = queryFrequency()
)

// queryFrequency returns the QueryPerformanceCounter frequency in ticks per
// second. It is fixed at boot and documented to never fail on Windows XP and
// later; 10 MHz (100 ns per tick) is typical.
func queryFrequency() int64 {
	var f int64
	if r, _, _ := procQPF.Call(uintptr(unsafe.Pointer(&f))); r == 0 || f <= 0 {
		panic("demo: QueryPerformanceFrequency failed")
	}
	return f
}

// ticks reads QueryPerformanceCounter.
func ticks() int64 {
	var c int64
	procQPC.Call(uintptr(unsafe.Pointer(&c)))
	return c
}

// ticksToNanos converts a tick difference to nanoseconds without overflowing
// for differences of any realistic uptime.
func ticksToNanos(d int64) int64 {
	f := counterFrequency
	return d/f*1e9 + d%f*1e9/f
}
