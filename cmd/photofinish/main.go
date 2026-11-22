// Command photofinish is the PhotoFinish CLI. Milestone M0 ships the demo target:
// a shop that is intentionally vulnerable to race conditions, with a fixed twin.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/TroubieD3v/photofinish/internal/demo"
)

// version is overridden at release time: -ldflags "-X main.version=v1.2.3"
var version = "0.0.0-dev"

const usage = `PhotoFinish - proves race conditions in web APIs

Usage:
  photofinish demo [--addr 127.0.0.1:8443] [--window 0s] [--expose] [--quiet]
  photofinish version
  photofinish help

Commands:
  demo      start the demo shop over HTTPS with HTTP/2: every scenario exists as
            /vuln (check-then-act, intentionally racy) and /fixed (atomic)
  version   print the version
  help      show this text

This is milestone M0, the demo target. The run, probe, import and serve
commands arrive in later milestones; see docs/DESIGN.ru.md for the design.
`

const demoUsage = `Usage: photofinish demo [--addr 127.0.0.1:8443] [--window 0s] [--expose] [--quiet]

Starts the demo shop. It is intentionally vulnerable to race conditions and
listens on loopback only unless --expose is given. State lives in memory.

Flags:
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the CLI with args (without the program name) and returns the exit code:
// 0 success, 1 runtime failure, 2 usage or validation error.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "demo":
		return cmdDemo(rest, stdout, stderr)
	case "version", "--version":
		fmt.Fprintln(stdout, "photofinish", version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return 2
	}
}

// errReported marks a flag error that the flag package has already printed with the usage text.
var errReported = errors.New("invalid flags")

// demoOptions holds the parsed flags of the demo command.
type demoOptions struct {
	addr   string
	window time.Duration
	expose bool
	quiet  bool
}

// parseDemo parses and validates the demo flags. Problems are reported on stderr.
func parseDemo(args []string, stderr io.Writer) (demoOptions, error) {
	var o demoOptions
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), demoUsage)
		fs.PrintDefaults()
	}
	fs.StringVar(&o.addr, "addr", "127.0.0.1:8443", "listen address (loopback only unless --expose)")
	fs.DurationVar(&o.window, "window", 0, "artificial pause between check and write in /vuln handlers (0s to 2s)")
	fs.BoolVar(&o.expose, "expose", false, "allow a non-loopback listen address (isolated lab networks only)")
	fs.BoolVar(&o.quiet, "quiet", false, "do not log requests")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return o, err
		}
		return o, fmt.Errorf("%w: %w", errReported, err)
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if _, _, err := net.SplitHostPort(o.addr); err != nil {
		return o, fmt.Errorf("--addr: %w", err)
	}
	if err := demo.ValidateAddr(o.addr, o.expose); err != nil {
		return o, fmt.Errorf("%w\nThe demo shop is intentionally vulnerable. Pass --expose to listen on %s anyway, on an isolated lab network only", err, o.addr)
	}
	// demo.New enforces the same cap; checking here fails before anything starts.
	if o.window < 0 || o.window > demo.MaxWindow {
		return o, fmt.Errorf("--window must be between 0s and %s, got %s", demo.MaxWindow, o.window)
	}
	return o, nil
}

func cmdDemo(args []string, stdout, stderr io.Writer) int {
	o, err := parseDemo(args, stderr)
	switch {
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, errReported):
		return 2
	case err != nil:
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runDemo(ctx, o, stdout, stderr, nil); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

// runDemo serves the demo shop until ctx is done. started, if non-nil, is called with the
// bound address after the banner is printed.
func runDemo(ctx context.Context, o demoOptions, stdout, stderr io.Writer, started func(addr string)) error {
	cfg := demo.Config{Window: o.window}
	if !o.quiet {
		cfg.Logger = log.New(stderr, "", log.Ltime|log.Lmicroseconds)
	}
	shop, err := demo.New(cfg)
	if err != nil {
		return err
	}
	defer shop.Close()

	if o.expose {
		fmt.Fprintf(stderr, "warning: --expose given; the intentionally vulnerable shop accepts connections on %s\n", o.addr)
	}
	ready := func(addr, fingerprint string) {
		printBanner(stdout, addr, fingerprint, o.window)
		if started != nil {
			started(addr)
		}
	}
	if err := demo.Serve(ctx, o.addr, shop, ready); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "stopped")
	return nil
}

func printBanner(w io.Writer, addr, fingerprint string, window time.Duration) {
	url := "https://" + addr
	win := "0s (no artificial pause; the race is real but narrow)"
	if window > 0 {
		win = window.String() + " (artificially widened in /vuln handlers)"
	}
	fmt.Fprintf(w, `PhotoFinish %s demo shop
intentionally vulnerable to race conditions - local testing only

  URL          %s
  Certificate  SHA-256 %s
               (self-signed, regenerated on every start)
  Variants     %s/vuln/api/...   check-then-act, racy
               %s/fixed/api/...  atomic
  Tokens       alice: Bearer demo-alice   bob: Bearer demo-bob
  State        in memory, lost on exit; POST /<variant>/api/reset restores the seed
  Window       %s
  Try          curl -k --http2 %s/

Ctrl+C to stop.
`, version, url, fingerprint, url, url, win, url)
}
