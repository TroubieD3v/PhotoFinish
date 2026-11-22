package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/TroubieD3v/photofinish/internal/engine"
)

const probeUsage = `Usage: photofinish probe <url> [--insecure]

Inspects a target without race traffic: TLS version, ALPN, whether HTTP/2
works, the server's HTTP/2 SETTINGS, the round-trip time of three GET requests
to the URL and whether responses carry an arrival-time header. Prints the
recommended engine. Probe only systems you are authorized to test.

Flags:
`

// probeOptions holds the parsed flags of the probe command.
type probeOptions struct {
	url      *url.URL
	insecure bool
}

// parseProbe parses and validates the probe flags. Problems are reported on stderr.
func parseProbe(args []string, stderr io.Writer) (probeOptions, error) {
	var o probeOptions
	fs := newFlagSet("probe", probeUsage, stderr)
	fs.BoolVar(&o.insecure, "insecure", false, "skip TLS certificate verification (self-signed lab targets)")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return o, err
	}
	switch len(pos) {
	case 0:
		return o, errors.New("probe needs a URL\n\n" + firstLine(probeUsage))
	case 1:
	default:
		return o, fmt.Errorf("probe takes one URL, got %d arguments", len(pos))
	}
	u, err := parseTargetURL(pos[0])
	if err != nil {
		return o, err
	}
	o.url = u
	return o, nil
}

// parseTargetURL accepts an absolute http or https URL with a host.
func parseTargetURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("URL %q must start with https:// or http://", s)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("URL %q has no host", s)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}

func cmdProbe(args []string, stdout, stderr io.Writer) int {
	o, err := parseProbe(args, stderr)
	if code, done := flagExit(err, stderr); done {
		return code
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	opts := engine.Options{Kind: engine.Auto, Guard: engine.AllowAll()}
	if o.insecure {
		opts.TLS = &tls.Config{InsecureSkipVerify: true} // the user asked for it: self-signed lab target
	}
	rep, err := engine.Probe(ctx, o.url, opts)
	if err != nil {
		fmt.Fprintf(stderr, "error: probe %s: %v\n", o.url, err)
		return exitFailure
	}
	writeProbe(stdout, rep)
	return exitOK
}

// writeProbe prints a probe report for humans.
func writeProbe(w io.Writer, r *engine.ProbeReport) {
	fmt.Fprintf(w, "probe %s\n", r.URL)
	if r.TLSVersion != "" || r.ALPN != "" {
		fmt.Fprintf(w, "  TLS          %s, ALPN %s\n", orDash(r.TLSVersion), orDash(r.ALPN))
	} else {
		fmt.Fprintf(w, "  TLS          none (plain HTTP)\n")
	}
	if r.HTTP2 {
		fmt.Fprintf(w, "  HTTP/2       yes\n")
		fmt.Fprintf(w, "  SETTINGS     max concurrent streams %s, initial window %d, max frame size %d\n",
			maxStreams(r.MaxConcurrentStreams), r.InitialWindowSize, r.MaxFrameSize)
	} else {
		fmt.Fprintf(w, "  HTTP/2       no\n")
	}
	fmt.Fprintf(w, "  Server       %s\n", orDash(r.Server))
	if len(r.Statuses) > 0 {
		fmt.Fprintf(w, "  Statuses     %s\n", strings.Trim(fmt.Sprint(r.Statuses), "[]"))
	}
	if len(r.RTTs) > 0 {
		parts := make([]string, len(r.RTTs))
		for i, d := range r.RTTs {
			parts[i] = formatMs(d)
		}
		fmt.Fprintf(w, "  Round trips  %s (median %s)\n", strings.Join(parts, ", "), formatMs(medianDuration(r.RTTs)))
	}
	if r.ArrivalHeader {
		fmt.Fprintf(w, "  Arrival      present: reports can show the server-side arrival spread\n")
	} else {
		fmt.Fprintf(w, "  Arrival      absent: only client-side timing is available\n")
	}
	fmt.Fprintf(w, "  Recommended  --engine %s\n", r.Recommended)
	for _, n := range r.Notes {
		fmt.Fprintf(w, "  note: %s\n", n)
	}
}

// maxStreams formats SETTINGS_MAX_CONCURRENT_STREAMS; 0 means the server did
// not send the setting, which HTTP/2 defines as unlimited.
func maxStreams(n uint32) string {
	if n == 0 {
		return "unlimited (not set)"
	}
	return fmt.Sprint(n)
}

// orDash returns s, or "-" if s is empty.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// medianDuration returns the median of ds, which must not be empty.
func medianDuration(ds []time.Duration) time.Duration {
	s := slices.Clone(ds)
	slices.Sort(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}
