// Command photofinish is the PhotoFinish CLI: it runs race scenarios against
// web APIs, probes targets, imports requests into scenario skeletons and
// serves the intentionally vulnerable demo shop.
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
	"runtime/debug"
	"syscall"
	"time"

	"github.com/TroubieD3v/photofinish/internal/demo"
)

// devVersion is the version of a build that sets none.
const devVersion = "0.0.0-dev"

// version is overridden at release time: -ldflags "-X main.version=v1.2.3".
// A binary built without it ("go install ...@v0.1.0") reports the module
// version that the go command recorded, see moduleVersion.
var version = devVersion

// Exit codes shared by the commands. The run command returns the verdict codes
// of runner.ExitCode instead: 0 HELD, 1 VIOLATED, 2 INCONCLUSIVE, 3 ERROR.
const (
	exitOK      = 0
	exitFailure = 1  // runtime failure of demo, probe or import
	exitUsage   = 64 // EX_USAGE: unknown command, bad flags or arguments
)

const usage = `PhotoFinish - proves race conditions in web APIs

Usage:
  photofinish run <scenario.yaml>... [--engine auto|h2|h1|burst] [--trials N] [--copies N]
                                     [--insecure] [--format text|json|sarif|junit|html] [--output FILE]
                                     [--out DIR] [--fail-on violated|inconclusive|never] [--quiet]
  photofinish probe <url> [--insecure]
  photofinish import <file> [--har-entry N] [--output scenario.yaml]
  photofinish demo [--addr 127.0.0.1:8443] [--window 0s] [--expose] [--quiet]
  photofinish version
  photofinish help

Commands:
  run       run scenarios: setup, a synchronized race and the invariant check,
            once per trial; exits 0 HELD, 1 VIOLATED, 2 INCONCLUSIVE, 3 ERROR
            (--fail-on never: 0 unless ERROR); reports as text, JSON, SARIF,
            JUnit XML or HTML
  probe     inspect a target (TLS, ALPN, HTTP/2 settings, round trips) and
            recommend an engine; sends three GET requests, no race traffic
  import    turn a raw HTTP request (Burp, DevTools) or a HAR file into a
            scenario skeleton
  demo      start the demo shop over HTTPS with HTTP/2: every scenario exists as
            /vuln (check-then-act, intentionally racy) and /fixed (atomic)
  version   print the version
  help      show this text

Run "photofinish <command> -h" for the flags of a command. Usage errors exit 64.
Test only systems you own or are explicitly authorized to test.

The serve command (web UI) arrives in milestone M4; see docs/DESIGN.ru.md for
the design.
`

const demoUsage = `Usage: photofinish demo [--addr 127.0.0.1:8443] [--window 0s] [--expose] [--quiet]

Starts the demo shop. It is intentionally vulnerable to race conditions and
listens on loopback only unless --expose is given. State lives in memory.

Flags:
`

func main() {
	if version == devVersion {
		if v, ok := moduleVersion(debug.ReadBuildInfo()); ok {
			version = v
		}
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// moduleVersion returns the version of the main module that the go command
// recorded in the binary: the resolved tag for "go install
// ...@v0" ("v0.1.0"), a pseudo-version for a commit. ok is false for a
// build without one ("(devel)").
func moduleVersion(info *debug.BuildInfo, ok bool) (string, bool) {
	if !ok || info == nil {
		return "", false
	}
	v := info.Main.Version
	if v == "" || v == "(devel)" {
		return "", false
	}
	return v, true
}

// run executes the CLI with args (without the program name) and returns the
// exit code: 0 success, 1 runtime failure, 64 usage error. The run command
// returns verdict codes instead (see cmdRun).
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "run":
		return cmdRun(rest, stdout, stderr)
	case "probe":
		return cmdProbe(rest, stdout, stderr)
	case "import":
		return cmdImport(rest, stdout, stderr)
	case "demo":
		return cmdDemo(rest, stdout, stderr)
	case "version", "--version":
		fmt.Fprintln(stdout, "photofinish", version)
		return exitOK
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return exitUsage
	}
}

// errReported marks a flag error that the flag package has already printed with the usage text.
var errReported = errors.New("invalid flags")

// flagExit maps the error returned by a command's flag parsing to an exit
// code. done is false when err is nil and the command should go on; any
// other error is a usage error, except -h, which exits 0.
func flagExit(err error, stderr io.Writer) (code int, done bool) {
	switch {
	case err == nil:
		return exitOK, false
	case errors.Is(err, flag.ErrHelp):
		return exitOK, true
	case errors.Is(err, errReported):
		return exitUsage, true
	default:
		fmt.Fprintln(stderr, "error:", err)
		return exitUsage, true
	}
}

// newFlagSet returns a flag set that reports problems on stderr and prints
// help followed by the flag defaults.
func newFlagSet(name, help string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), help)
		fs.PrintDefaults()
	}
	return fs
}

// parseFlags parses args with fs and, unlike fs.Parse, accepts flags after
// positional arguments, as in "run a.yaml b.yaml --trials 5". Everything after
// "--" is positional. It returns the positional arguments in order. Flag
// errors are wrapped in errReported because fs has already printed them.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, fmt.Errorf("%w: %w", errReported, err)
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		if consumed := len(args) - len(rest); consumed > 0 && args[consumed-1] == "--" {
			return append(pos, rest...), nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

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
	if code, done := flagExit(err, stderr); done {
		return code
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runDemo(ctx, o, stdout, stderr, nil); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitFailure
	}
	return exitOK
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
