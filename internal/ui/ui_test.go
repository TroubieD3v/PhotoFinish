package ui

import (
	"io/fs"
	"testing"
)

func TestFS(t *testing.T) {
	fsys := FS()
	if fsys == nil {
		t.Fatal("FS returned nil")
	}
	_, err := fs.Stat(fsys, "index.html")
	if Built() != (err == nil) {
		t.Errorf("Built() = %v, but stat index.html: %v", Built(), err)
	}
	// The placeholder is outside the UI root and must not be served.
	if _, err := fs.Stat(fsys, "README.md"); err == nil {
		t.Error("README.md of dist is visible in the UI file system")
	}
}
