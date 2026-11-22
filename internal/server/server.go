// Package server is the local API behind the PhotoFinish web UI: it lists and
// edits the scenario files of one workspace directory, validates scenarios,
// runs them one at a time, streams their progress, keeps the history in a
// store and serves the embedded UI.
//
// The server sends attack traffic on request, so it must not be drivable by
// web pages the user happens to visit. Every /api request except
// /api/health needs the session token as a bearer token; the Host header
// must name the loopback listener (DNS rebinding defence) unless the server
// was exposed explicitly; writes with a foreign Origin are rejected; and
// every response carries a strict Content-Security-Policy. File access is
// confined to the workspace. Scope and budget of a run are enforced by the
// runner, exactly as for "photofinish run".
package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/TroubieD3v/photofinish/examples"
	"github.com/TroubieD3v/photofinish/internal/demo"
	"github.com/TroubieD3v/photofinish/internal/store"
)

// Limits of the API.
const (
	// MaxBodyBytes caps every request body.
	MaxBodyBytes = 1 << 20
	// MaxFileBytes caps a scenario file read from or written to the
	// workspace, and scenario content sent for validation or a run.
	MaxFileBytes = 256 << 10
	// MinTokenLength is the shortest accepted session token.
	MinTokenLength = 32
	// DefaultDemoAddr is where the in-process demo shop listens; the
	// examples point at it.
	DefaultDemoAddr = "127.0.0.1:8443"
)

// ContentSecurityPolicy is sent with every response.
const ContentSecurityPolicy = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; " +
	"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// Store keeps the run history; *store.Store implements it.
type Store interface {
	Save(r *store.Run) error
	Get(id string) (*store.Run, error)
	List(limit int, scenario string) ([]store.Run, error)
	Query(f store.Filter) ([]store.Run, error)
	LatestByFile() (map[string]store.Run, error)
	Scenarios() ([]string, error)
	Delete(id string) error
}

// Config configures a Server.
type Config struct {
	// Version is reported by /api/health and written to reports.
	Version string
	// Workspace is the directory whose *.yaml and *.yml files the API
	// lists and edits; it must exist.
	Workspace string
	// Token is the session token every /api request (except /api/health)
	// must present as "Authorization: Bearer <token>". It must be at least
	// MinTokenLength characters long.
	Token string
	// Store keeps the run history; it is required.
	Store Store
	// DataDir is the directory of the store, reported by /api/info; ""
	// means the history is kept in memory.
	DataDir string
	// UI is the built web interface rooted at index.html; nil or an empty
	// file system serves a page that says the UI was not built.
	UI fs.FS
	// Expose accepts any Host header. The listener may then be reachable
	// from other machines; the token still protects the API.
	Expose bool
	// DemoAddr is the listen address of the in-process demo shop;
	// "" means DefaultDemoAddr. It must be a loopback address.
	DemoAddr string
	// DemoWindow is the artificial pause of the demo shop's /vuln
	// handlers, as "photofinish demo --window"; 0 to demo.MaxWindow.
	DemoWindow time.Duration
	// Examples holds the example scenarios (*.yaml at the root); nil means
	// the examples embedded in the binary.
	Examples fs.FS
	// Logger receives errors that cannot be reported to a client, such as
	// a run that could not be saved. nil discards them.
	Logger *log.Logger
}

// Server is the API server. Create it with New and release it with Close.
type Server struct {
	version   string
	workspace string   // absolute, symlinks resolved
	root      *os.Root // confines every file access to workspace
	tokenHash [sha256.Size]byte
	store     Store
	dataDir   string
	ui        fs.FS
	expose    bool
	examples  fs.FS
	logger    *log.Logger

	// ctx is the parent of every run; Close cancels it.
	ctx    context.Context
	cancel context.CancelFunc

	runs *runs
	demo *demoShop
	// fileMu serializes the compare-and-write of PUT /api/scenarios/file.
	fileMu sync.Mutex

	closeOnce sync.Once
}

// New validates cfg and returns a Server.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		return nil, errors.New("server: a store is required")
	}
	if err := CheckToken(cfg.Token); err != nil {
		return nil, err
	}
	ws := cfg.Workspace
	if ws == "" {
		ws = "."
	}
	abs, err := filepath.Abs(ws)
	if err != nil {
		return nil, fmt.Errorf("workspace: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	if fi, err := os.Stat(abs); err != nil {
		return nil, fmt.Errorf("workspace: %w", err)
	} else if !fi.IsDir() {
		return nil, fmt.Errorf("workspace %s is not a directory", abs)
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, fmt.Errorf("workspace: %w", err)
	}
	demoAddr := cfg.DemoAddr
	if demoAddr == "" {
		demoAddr = DefaultDemoAddr
	}
	if err := checkLoopbackAddr(demoAddr); err != nil {
		root.Close()
		return nil, fmt.Errorf("demo address: %w", err)
	}
	if cfg.DemoWindow < 0 || cfg.DemoWindow > demo.MaxWindow {
		root.Close()
		return nil, fmt.Errorf("demo window must be between 0s and %s, got %s", demo.MaxWindow, cfg.DemoWindow)
	}
	ex := cfg.Examples
	if ex == nil {
		ex = examples.FS
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		version:   valueOr(cfg.Version, "dev"),
		workspace: abs,
		root:      root,
		tokenHash: sha256.Sum256([]byte(cfg.Token)),
		store:     cfg.Store,
		dataDir:   cfg.DataDir,
		ui:        cfg.UI,
		expose:    cfg.Expose,
		examples:  ex,
		logger:    logger,
		ctx:       ctx,
		cancel:    cancel,
		demo:      newDemoShop(demoAddr, cfg.DemoWindow),
	}
	s.runs = newRuns()
	return s, nil
}

// CheckToken reports whether token is acceptable as a session token: at
// least MinTokenLength characters of printable ASCII without spaces, so that
// it fits an Authorization header and a URL fragment unchanged.
func CheckToken(token string) error {
	if len(token) < MinTokenLength {
		return fmt.Errorf("the session token must be at least %d characters long, got %d", MinTokenLength, len(token))
	}
	for i := 0; i < len(token); i++ {
		if c := token[i]; c <= ' ' || c > '~' || c == '#' || c == '%' || c == '&' {
			return errors.New("the session token may only contain printable ASCII characters other than space, #, % and &")
		}
	}
	return nil
}

// Workspace returns the absolute path of the workspace.
func (s *Server) Workspace() string { return s.workspace }

// Close cancels a running run and waits for it to be saved, stops the demo
// shop and releases the workspace. It is safe to call more than once.
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.cancel()
		s.runs.wait()
		err = errors.Join(s.demo.stop(), s.root.Close())
	})
	return err
}

// Handler returns the root handler with every security check applied.
func (s *Server) Handler() http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("GET /api/health", s.health)
	api.HandleFunc("GET /api/info", s.info)
	api.HandleFunc("GET /api/scenarios", s.listScenarios)
	api.HandleFunc("GET /api/scenarios/file", s.getFile)
	api.HandleFunc("PUT /api/scenarios/file", s.putFile)
	api.HandleFunc("DELETE /api/scenarios/file", s.deleteFile)
	api.HandleFunc("POST /api/scenarios/validate", s.validate)
	api.HandleFunc("POST /api/examples/{name}/copy", s.copyExample)
	api.HandleFunc("POST /api/import", s.importRequest)
	api.HandleFunc("POST /api/probe", s.probe)
	api.HandleFunc("POST /api/runs", s.startRun)
	api.HandleFunc("GET /api/runs", s.listRuns)
	api.HandleFunc("GET /api/runs/scenarios", s.runScenarios)
	api.HandleFunc("GET /api/runs/{id}", s.getRun)
	api.HandleFunc("DELETE /api/runs/{id}", s.deleteRun)
	api.HandleFunc("POST /api/runs/{id}/cancel", s.cancelRun)
	api.HandleFunc("GET /api/runs/{id}/events", s.runEvents)
	api.HandleFunc("GET /api/runs/{id}/{file}", s.runReport)
	api.HandleFunc("POST /api/demo/start", s.demoStart)
	api.HandleFunc("POST /api/demo/stop", s.demoStop)
	api.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		fail(w, http.StatusNotFound, errors.New("no such API route"))
	})

	mux := http.NewServeMux()
	mux.Handle("/api/", s.guardAPI(api))
	mux.Handle("/", s.spa())
	return s.secure(mux)
}

// secure sets the security headers on every response and rejects requests
// whose Host header does not name this server (DNS rebinding).
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", ContentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if isAPI(r.URL.Path) {
			h.Set("Cache-Control", "no-store")
		}
		if !s.expose && !s.allowedHost(r) {
			fail(w, http.StatusMisdirectedRequest, fmt.Errorf("host %q is not this server; open the URL printed by photofinish serve", r.Host))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// guardAPI enforces the Origin check on writes and the session token on
// every API route except /api/health.
func (s *Server) guardAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isWrite(r.Method) {
			if err := sameOrigin(r); err != nil {
				fail(w, http.StatusForbidden, err)
				return
			}
		}
		if r.URL.Path != "/api/health" && !s.authorized(r) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="photofinish"`)
			fail(w, http.StatusUnauthorized, errors.New("missing or wrong session token: open the URL printed by photofinish serve"))
			return
		}
		if isWrite(r.Method) && r.ContentLength != 0 {
			ct := r.Header.Get("Content-Type")
			if mt, _, _ := strings.Cut(ct, ";"); !strings.EqualFold(strings.TrimSpace(mt), "application/json") {
				fail(w, http.StatusUnsupportedMediaType, errors.New("the request body must be application/json"))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// isAPI reports whether path belongs to the API.
func isAPI(path string) bool {
	return path == "/api" || strings.HasPrefix(path, "/api/")
}

// isWrite reports whether method changes state.
func isWrite(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// authorized compares the bearer token in constant time. Both sides are
// hashed first, so that the comparison does not leak the token length.
func (s *Server) authorized(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	scheme, tok, ok := strings.Cut(auth, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	got := sha256.Sum256([]byte(strings.TrimSpace(tok)))
	return subtle.ConstantTimeCompare(got[:], s.tokenHash[:]) == 1
}

// allowedHost reports whether the Host header is one of the loopback names
// of this server with the port the connection arrived on.
func (s *Server) allowedHost(r *http.Request) bool {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil || port == "" {
		return false
	}
	local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return false
	}
	_, localPort, err := net.SplitHostPort(local.String())
	if err != nil || localPort != port {
		return false
	}
	// A loopback IP literal cannot be rebound to another address; a name
	// other than localhost could be.
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback() && !strings.Contains(host, "%")
}

// sameOrigin rejects a request whose Origin header (if any) is not this
// server, and requests that the browser marks as cross-site.
func sameOrigin(r *http.Request) error {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return fmt.Errorf("cross-site request rejected (Sec-Fetch-Site: %s)", site)
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return nil
	}
	rest, ok := strings.CutPrefix(origin, "http://")
	if !ok {
		rest, ok = strings.CutPrefix(origin, "https://")
	}
	if !ok || !strings.EqualFold(rest, r.Host) {
		return fmt.Errorf("cross-origin request rejected (Origin %q)", origin)
	}
	return nil
}

// checkLoopbackAddr rejects a host:port whose host is not a loopback address.
func checkLoopbackAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", addr, err)
	}
	if !IsLoopbackHost(host) {
		return fmt.Errorf("%q is not a loopback address", addr)
	}
	return nil
}

// IsLoopbackHost reports whether host names the local machine only:
// localhost, 127.0.0.0/8 or ::1.
func IsLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// health answers without a token, so that scripts can wait for the server.
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.version})
}

// infoResponse is the body of GET /api/info.
type infoResponse struct {
	Version    string     `json:"version"`
	Workspace  string     `json:"workspace"`
	Demo       demoStatus `json:"demo"`
	DataDir    string     `json:"dataDir"`
	RunningRun string     `json:"runningRun"`
}

func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, infoResponse{
		Version:    s.version,
		Workspace:  s.workspace,
		Demo:       s.demo.status(),
		DataDir:    s.dataDir,
		RunningRun: s.runs.activeID(),
	})
}

// writeJSON writes v as JSON with status code. HTML escaping is off, as in
// the reports, so that invariants such as "a <= 1" stay readable.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// errorBody is the body of every error response.
type errorBody struct {
	Error string `json:"error"`
	// ID is the running run of a 409 from POST /api/runs.
	ID string `json:"id,omitempty"`
	// Hash is the current hash of a file in a 409 from PUT.
	Hash string `json:"hash,omitempty"`
}

// fail writes err as {"error": "..."}.
func fail(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, errorBody{Error: err.Error()})
}

// readJSON decodes the request body into v, capped at MaxBodyBytes. It
// writes the error response and returns false when the body is too large or
// not a single JSON value.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	body := http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	dec := json.NewDecoder(body)
	err := dec.Decode(v)
	if err == nil {
		if dec.More() {
			err = errors.New("unexpected data after the JSON value")
		} else if _, terr := dec.Token(); terr != io.EOF {
			err = errors.New("unexpected data after the JSON value")
		}
	}
	if err == nil {
		return true
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		fail(w, http.StatusRequestEntityTooLarge, fmt.Errorf("the request body is larger than %d KiB", MaxBodyBytes>>10))
		return false
	}
	if errors.Is(err, io.EOF) {
		err = errors.New("the request body is empty")
	}
	fail(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
	return false
}

// valueOr returns v, or def when v is empty.
func valueOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
