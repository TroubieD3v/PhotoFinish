package examples

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/TroubieD3v/photofinish/internal/scenario"
)

func TestNamesMatchFiles(t *testing.T) {
	files, err := filepath.Glob("*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, f := range files {
		want = append(want, strings.TrimSuffix(f, ".yaml"))
	}
	slices.Sort(want)
	got := Names()
	if len(got) == 0 || !slices.Equal(got, want) {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
	for _, name := range []string{"coupon-vuln", "coupon-fixed"} {
		if !slices.Contains(got, name) {
			t.Errorf("Names() lacks %s", name)
		}
	}
}

func TestExamplesAreValidAndTargetTheDemo(t *testing.T) {
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			data, err := Read(name)
			if err != nil {
				t.Fatal(err)
			}
			disk, err := os.ReadFile(name + ".yaml")
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != string(disk) {
				t.Error("embedded content differs from the file")
			}
			s, err := scenario.Parse(data, "examples/"+name+".yaml")
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if err := s.Validate(); err != nil {
				t.Fatalf("validate: %v", err)
			}
			if s.Name != name {
				t.Errorf("scenario name %q, want %q", s.Name, name)
			}
			if !strings.HasPrefix(s.Target, "https://127.0.0.1:8443/") {
				t.Errorf("target %q does not point at the demo shop", s.Target)
			}
		})
	}
}

func TestReadUnknown(t *testing.T) {
	for _, name := range []string{"", "missing", "../go.mod", "coupon-vuln.yaml", "./coupon-vuln", "COUPON-VULN"} {
		if _, err := Read(name); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Read(%q) error %v, want fs.ErrNotExist", name, err)
		}
	}
}
