package server

import "syscall"

// shortName returns the 8.3 short name of the last element of path, or ""
// when the volume has none.
func shortName(path string) string {
	long, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	buf := make([]uint16, 1024)
	n, err := syscall.GetShortPathName(long, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) > len(buf) {
		return ""
	}
	s := syscall.UTF16ToString(buf[:n])
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == 0x5c {
			return s[i+1:]
		}
	}
	return s
}
