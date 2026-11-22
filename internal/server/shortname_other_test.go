//go:build !windows

package server

// shortName returns "": only Windows has 8.3 short names.
func shortName(string) string { return "" }
