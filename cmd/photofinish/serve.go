package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TroubieD3v/photofinish/internal/demo"
	"github.com/TroubieD3v/photofinish/internal/server"
	"github.com/TroubieD3v/photofinish/internal/store"
	"github.com/TroubieD3v/photofinish/internal/ui"
)

const serveUsage = `Usage: photofinish serve [--addr 127.0.0.1:7340] [--workspace DIR] [--data DIR]
                        [--demo] [--demo-addr 127.0.0.1:8443] [--demo-window 0s]
                        [--expose] [--open]

Serves the web UI and its local API: edit and validate the scenarios of the
workspace, run them, follow the trials live, keep the run history and
download reports.

The server sends race traffic on request, so web pages must not be able to
drive it. It listens on loopback only unless --expose is given; every API
request needs the session token, printed once on start as part of the UI
link (or taken from PHOTOFINISH_TOKEN, at least 32 characters); requests
for other host names (DNS rebinding) and cross-origin writes are rejected.
Only *.yaml and *.yml files inside the workspace are accessible. Scope and
budget of every scenario are enforced as for "photofinish run".

The run history is kept in DIR/photofinish.db; --data "" or --data :memory:
keeps it in memory.

Flags:
`

// defaultServeAddr is the default listen address of serve.
const defaultServeAddr = "127.0.0.1:7340"

// tokenEnv is the environment variable that sets the session token.
const tokenEnv = "PHOTOFINISH_TOKEN"

// Server timeouts. There is no write timeout: the progress stream of a run
// stays open as long as the run.
const (
	serveReadHeaderTimeout = 10 * time.Second
	serveReadTimeout       = time.Minute
	serveIdleTimeout       = 2 * time.Minute
	serveMaxHeaderBytes    = 64 << 10
	serveShutdownTimeout   = 5 * time.Second
)

// serveOptions holds the parsed flags of the serve command.
type serveOptions struct {
	addr      string
	workspace string
	data      string
	demo      bool
	demoAddr  string
	demoWin   time.Duration
	expose    bool
	open      bool
	token     string
}

// getenv reads the environment; tests replace it.
var getenv = os.Getenv

// defaultDataDir returns the default --data directory: photofinish in the
// user's configuration directory.
func defaultDataDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "photofinish")
}

// parseServe parses and validates the serve flags. Problems are reported on stderr.
func parseServe(args []string, stderr io.Writer) (serveOptions, error) {
	var o serveOptions
	fs := newFlagSet("serve", serveUsage, stderr)
	fs.StringVar(&o.addr, "addr", defaultServeAddr, "listen address (loopback only unless --expose)")
	fs.StringVar(&o.workspace, "workspace", ".", "directory with the scenario files the UI lists and edits")
	defData := defaultDataDir()
	fs.StringVar(&o.data, "data", defData, `directory of the run history ("" or :memory: keeps it in memory)`)
	fs.BoolVar(&o.demo, "demo", false, "start the demo shop on start (it can also be started from the UI)")
	fs.StringVar(&o.demoAddr, "demo-addr", server.DefaultDemoAddr, "listen address of the demo shop, loopback only (the examples expect 127.0.0.1:8443)")
	fs.DurationVar(&o.demoWin, "demo-window", 0, "artificial pause between check and write in the /vuln handlers of the demo shop (0s to 2s), as demo --window")
	fs.BoolVar(&o.expose, "expose", false, "allow a non-loopback listen address and any Host header (containers, isolated lab networks); the token still protects the API")
	fs.BoolVar(&o.open, "open", false, "open the UI in the default browser")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return o, err
	}
	if len(pos) > 0 {
		return o, fmt.Errorf("unexpected argument %q", pos[0])
	}
	dataSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "data" {
			dataSet = true
		}
	})
	if !dataSet && defData == "" {
		return o, errors.New("no user configuration directory for the run history; set --data DIR (or --data :memory:)")
	}

	host, _, err := net.SplitHostPort(o.addr)
	if err != nil {
		return o, fmt.Errorf("--addr: %w", err)
	}
	if !o.expose && !server.IsLoopbackHost(host) {
		return o, fmt.Errorf("refusing to listen on %q: the server sends race traffic on request, so it only binds to "+
			"loopback (127.0.0.1, ::1, localhost) unless --expose is given", o.addr)
	}
	if h, _, err := net.SplitHostPort(o.demoAddr); err != nil {
		return o, fmt.Errorf("--demo-addr: %w", err)
	} else if !server.IsLoopbackHost(h) {
		return o, fmt.Errorf("--demo-addr %q: the demo shop is intentionally vulnerable and listens on loopback only", o.demoAddr)
	}
	if o.demoWin < 0 || o.demoWin > demo.MaxWindow {
		return o, fmt.Errorf("--demo-window must be between 0s and %s, got %s", demo.MaxWindow, o.demoWin)
	}
	fi, err := os.Stat(o.workspace)
	if err != nil {
		return o, fmt.Errorf("--workspace: %w", err)
	}
	if !fi.IsDir() {
		return o, fmt.Errorf("--workspace %s is not a directory", o.workspace)
	}

	o.token = getenv(tokenEnv)
	if o.token != "" {
		if err := server.CheckToken(o.token); err != nil {
			return o, fmt.Errorf("%s: %w", tokenEnv, err)
		}
	} else {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return o, err
		}
		o.token = hex.EncodeToString(b)
	}
	return o, nil
}

func cmdServe(args []string, stdout, stderr io.Writer) int {
	o, err := parseServe(args, stderr)
	if code, done := flagExit(err, stderr); done {
		return code
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runServe(ctx, o, stdout, stderr, nil); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitFailure
	}
	return exitOK
}

// openBrowser opens target, a file path or URL, in the default browser;
// tests replace it.
var openBrowser = func(target string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	case "darwin":
		cmd = exec.Command("open", target)
	default:
		cmd = exec.Command("xdg-open", target)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }() // reap the launcher; the browser keeps running
	return nil
}

// redirectKeep is how long the redirect page of --open stays on disk at
// most; it is removed earlier when the server stops.
const redirectKeep = 2 * time.Minute

// redirectPage is the page --open opens: it moves on to the UI link at
// once, so that the token reaches the browser without being on the command
// line of the launcher or of a browser it starts, where other local users
// could read it (ps, /proc/<pid>/cmdline).
var redirectPage = template.Must(template.New("open").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<meta http-equiv="refresh" content="0;url={{.}}">
<title>PhotoFinish</title>
<script>window.location.replace({{.}});</script>
</head>
<body><p>Opening <a href="{{.}}">PhotoFinish</a>.</p></body>
</html>
`))

// openLink opens the UI link through a redirect page in a new private
// temporary directory: the page is readable by the owner only and the
// command line carries only its path. The returned function removes the
// directory; it is safe to call more than once.
func openLink(link string) (cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "photofinish-open-")
	if err != nil {
		return func() {}, err
	}
	var once sync.Once
	cleanup = func() { once.Do(func() { _ = os.RemoveAll(dir) }) }
	var buf bytes.Buffer
	if err := redirectPage.Execute(&buf, template.URL(link)); err != nil {
		cleanup()
		return func() {}, err
	}
	page := filepath.Join(dir, "open.html")
	if err := os.WriteFile(page, buf.Bytes(), 0o600); err != nil {
		cleanup()
		return func() {}, err
	}
	if err := openBrowser(page); err != nil {
		cleanup()
		return func() {}, err
	}
	time.AfterFunc(redirectKeep, cleanup)
	return cleanup, nil
}

// runServe serves the UI and the API until ctx is done. started, if non-nil,
// is called with the bound address after the UI link is printed.
func runServe(ctx context.Context, o serveOptions, stdout, stderr io.Writer, started func(addr string)) error {
	st, err := store.Open(store.Path(o.data))
	if err != nil {
		return err
	}
	defer st.Close()
	dataDir := ""
	if store.Path(o.data) != store.Memory {
		if abs, err := filepath.Abs(o.data); err == nil {
			dataDir = abs
		}
	}

	srv, err := server.New(server.Config{
		Version:    version,
		Workspace:  o.workspace,
		Token:      o.token,
		Store:      st,
		DataDir:    dataDir,
		UI:         ui.FS(),
		Expose:     o.expose,
		DemoAddr:   o.demoAddr,
		DemoWindow: o.demoWin,
		Logger:     log.New(stderr, "", log.Ltime),
	})
	if err != nil {
		return err
	}
	defer srv.Close()

	ln, err := net.Listen("tcp", o.addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()
	if o.demo {
		if err := srv.StartDemo(); err != nil {
			return err
		}
	}

	baseCtx, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()
	hs := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: serveReadHeaderTimeout,
		ReadTimeout:       serveReadTimeout,
		IdleTimeout:       serveIdleTimeout,
		MaxHeaderBytes:    serveMaxHeaderBytes,
		ErrorLog:          log.New(io.Discard, "", 0),
		// Cancelling the base context ends the progress streams on shutdown.
		BaseContext: func(net.Listener) context.Context { return baseCtx },
	}

	if o.expose {
		fmt.Fprintf(stderr, "warning: --expose given; the API accepts connections on %s and any Host header; only the session token protects it\n", ln.Addr())
	}
	link := uiURL(ln.Addr().String()) + "#token=" + o.token
	fmt.Fprintf(stdout, "PhotoFinish UI: %s\n", link)
	fmt.Fprintf(stdout, "  workspace  %s\n", srv.Workspace())
	if dataDir == "" {
		fmt.Fprintf(stdout, "  history    in memory\n")
	} else {
		fmt.Fprintf(stdout, "  history    %s\n", store.Path(dataDir))
	}
	if o.demo {
		fmt.Fprintf(stdout, "  demo shop  %s (intentionally vulnerable, local testing only)\n", srv.DemoURL())
	}
	if !ui.Built() {
		fmt.Fprintln(stdout, "  note       the web UI was not built into this binary (make ui, then make build); the API works")
	}
	fmt.Fprintln(stdout, "Ctrl+C to stop.")
	if o.open {
		cleanup, err := openLink(link)
		defer cleanup()
		if err != nil {
			fmt.Fprintf(stderr, "warning: could not open a browser: %v\n", err)
		}
	}
	if started != nil {
		started(ln.Addr().String())
	}

	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(ln) }()
	select {
	case err := <-errc:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}
	cancelBase()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), serveShutdownTimeout)
	defer cancel()
	if err := hs.Shutdown(shutdownCtx); err != nil {
		hs.Close()
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	if err := srv.Close(); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "stopped")
	return nil
}

// uiURL returns the http URL for a bound address: unspecified addresses
// (0.0.0.0, ::) are shown as the loopback address of the same family.
func uiURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr + "/"
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		if ip.To4() != nil {
			host = "127.0.0.1"
		} else {
			host = "::1"
		}
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(strings.Trim(host, "[]"), port) + "/"
}
