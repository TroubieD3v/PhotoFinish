package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/TroubieD3v/photofinish/internal/scenario"
)

const importUsage = `Usage: photofinish import <file> [--har-entry N] [--output scenario.yaml]

Turns a captured request into a scenario skeleton. The format is detected:
a HAR file (JSON with log.entries, e.g. exported from browser DevTools) or a
raw HTTP request (e.g. copied from Burp). The skeleton is written to stdout,
or to --output (an existing file is never overwritten).

The skeleton does not run as is: fill in the check request and the invariant,
review scope and budget, and move credentials to ${env:NAME}.

Flags:
`

// maxImportBytes caps the size of an imported file.
const maxImportBytes = 64 << 20

// importOptions holds the parsed flags of the import command.
type importOptions struct {
	file     string
	harEntry int
	output   string
}

// parseImport parses and validates the import flags. Problems are reported on stderr.
func parseImport(args []string, stderr io.Writer) (importOptions, error) {
	var o importOptions
	fs := newFlagSet("import", importUsage, stderr)
	fs.IntVar(&o.harEntry, "har-entry", 0, "index of the HAR entry to import (0: the first)")
	fs.StringVar(&o.output, "output", "", "write the scenario to `FILE` instead of stdout")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return o, err
	}
	switch len(pos) {
	case 0:
		return o, errors.New("import needs a file\n\n" + firstLine(importUsage))
	case 1:
	default:
		return o, fmt.Errorf("import takes one file, got %d arguments", len(pos))
	}
	if o.harEntry < 0 {
		return o, fmt.Errorf("--har-entry must not be negative, got %d", o.harEntry)
	}
	o.file = pos[0]
	return o, nil
}

func cmdImport(args []string, stdout, stderr io.Writer) int {
	o, err := parseImport(args, stderr)
	if code, done := flagExit(err, stderr); done {
		return code
	}
	data, err := readLimited(o.file, maxImportBytes)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitFailure
	}

	var s *scenario.Scenario
	format := "raw HTTP request"
	if entries, ok := harEntries(data); ok {
		format = "HAR"
		if entries == 0 {
			fmt.Fprintf(stderr, "error: %s has no HAR entries (log.entries is empty)\n", o.file)
			return exitFailure
		}
		if o.harEntry >= entries {
			fmt.Fprintf(stderr, "error: --har-entry %d: %s has %d entries (0 to %d)\n", o.harEntry, o.file, entries, entries-1)
			return exitUsage
		}
		s, err = scenario.ImportHAR(data, o.harEntry)
	} else {
		if o.harEntry != 0 {
			fmt.Fprintf(stderr, "error: --har-entry given, but %s is not a HAR file (JSON with log.entries)\n", o.file)
			return exitUsage
		}
		s, err = scenario.ImportBurp(data)
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: import %s (%s): %v\n", o.file, format, err)
		return exitFailure
	}
	out, err := scenario.Marshal(s)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitFailure
	}

	notes := stdout
	if o.output == "" {
		if _, err := stdout.Write(out); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitFailure
		}
		notes = stderr // keep stdout a valid scenario file
	} else {
		if err := writeNewFile(o.output, out); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitFailure
		}
		fmt.Fprintf(notes, "wrote %s (from %s, %s)\n", o.output, o.file, format)
	}
	writeImportNotes(notes, out)
	return exitOK
}

// readLimited reads a whole file, refusing files larger than limit bytes.
func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d MiB", path, limit>>20)
	}
	return data, nil
}

// harEntries reports whether data is a HAR document, that is a JSON object
// with log.entries, and how many entries it has.
func harEntries(data []byte) (int, bool) {
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))) // drop a UTF-8 byte order mark
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return 0, false
	}
	var doc struct {
		Log *struct {
			Entries []json.RawMessage `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(trimmed, &doc); err != nil || doc.Log == nil || doc.Log.Entries == nil {
		return 0, false
	}
	return len(doc.Log.Entries), true
}

// writeNewFile creates path with data and fails if the file already exists.
func writeNewFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; choose another --output or remove it", path)
		}
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// credentialHeader matches YAML lines that carry a header which usually holds
// a credential.
var credentialHeader = regexp.MustCompile(`(?im)^[\s"'-]*(authorization|proxy-authorization|cookie|x-api-key|x-auth-token)\s*["']?\s*:`)

// writeImportNotes tells the user what the skeleton still needs.
func writeImportNotes(w io.Writer, out []byte) {
	fmt.Fprintln(w, "before running the scenario:")
	fmt.Fprintln(w, "  - write the check: a check request and check.invariant (the placeholder fails validation on purpose)")
	fmt.Fprintln(w, "  - review scope.allow_hosts and set scope.budget (defaults: 1000 requests per run, 20 rps outside the race)")
	fmt.Fprintln(w, "  - add setup steps that create fresh state for every trial, and reset steps if needed")
	var found []string
	for _, m := range credentialHeader.FindAllSubmatch(out, -1) {
		h := strings.ToLower(string(m[1]))
		if !slices.Contains(found, h) {
			found = append(found, h)
		}
	}
	if len(found) > 0 {
		fmt.Fprintf(w, "  - the request carries %s: move the values to identities with ${env:NAME} before sharing the file\n",
			strings.Join(found, ", "))
	}
	if bytes.Contains(out, []byte(`{{"{{"}}`)) || bytes.Contains(out, []byte(`{{"${env:"}}`)) {
		fmt.Fprintln(w, `  - the request contains "{{" or "${env:"; they are written as the literals {{"{{"}} and {{"${env:"}} so that they are sent as captured`)
	}
}
