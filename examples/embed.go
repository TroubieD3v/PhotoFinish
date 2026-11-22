// Package examples embeds the example scenarios for the demo shop, so that
// the binary can offer them without the source tree. The files keep
// pointing at the demo's address, https://127.0.0.1:8443.
package examples

import (
	"embed"
	"io/fs"
	"slices"
	"strings"
)

// FS holds the example scenario files, *.yaml at its root.
//
//go:embed *.yaml
var FS embed.FS

// ext is the extension of every example file.
const ext = ".yaml"

// Names returns the example names, the file names without ".yaml", sorted.
func Names() []string {
	entries, err := fs.ReadDir(FS, ".")
	if err != nil {
		return nil // cannot happen with an embedded directory
	}
	var names []string
	for _, e := range entries {
		if name, ok := strings.CutSuffix(e.Name(), ext); ok && !e.IsDir() {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// Read returns the content of the example called name (as listed by
// Names). An unknown name returns an error wrapping fs.ErrNotExist.
func Read(name string) ([]byte, error) {
	if !slices.Contains(Names(), name) {
		return nil, &fs.PathError{Op: "read", Path: name + ext, Err: fs.ErrNotExist}
	}
	return FS.ReadFile(name + ext)
}
