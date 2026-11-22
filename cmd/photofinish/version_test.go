package main

import (
	"runtime/debug"
	"testing"
)

// TestModuleVersion checks the version that a binary without -X main.version
// reports: the module version the go command recorded, if any.
func TestModuleVersion(t *testing.T) {
	for _, tc := range []struct {
		info *debug.BuildInfo
		ok   bool
		want string
	}{
		{&debug.BuildInfo{Main: debug.Module{Version: "v0.1.0"}}, true, "v0.1.0"},
		{&debug.BuildInfo{Main: debug.Module{Version: "v0.1.1-0.20261122100000-0123456789ab"}}, true, "v0.1.1-0.20261122100000-0123456789ab"},
		{&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true, ""},
		{&debug.BuildInfo{}, true, ""},
		{nil, false, ""},
	} {
		got, ok := moduleVersion(tc.info, tc.ok)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("moduleVersion(%+v) = %q, %v; want %q", tc.info, got, ok, tc.want)
		}
	}
}
