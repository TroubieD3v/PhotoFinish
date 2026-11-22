// Package demo implements the PhotoFinish demo shop: a small HTTP API that
// exists twice, once with intentional check-then-act race conditions under
// /vuln and once with atomic operations under /fixed. Each variant has its
// own in-memory SQLite database, so both can be attacked side by side.
//
// The shop is intentionally vulnerable and meant for local testing only.
package demo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TroubieD3v/photofinish/internal/clock"
	"io"
	"log"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
)

// Variant names one of the two copies of the shop.
type Variant string

// The two variants served by the shop.
const (
	// Vulnerable is the check-then-act variant served under /vuln.
	Vulnerable Variant = "vuln"
	// Fixed is the atomic variant served under /fixed.
	Fixed Variant = "fixed"
)

// MaxWindow is the largest artificial race window New accepts. It stays well
// below the server write timeout.
const MaxWindow = 2 * time.Second

// Request limits and fixed header names.
const (
	maxBodyBytes  = 64 << 10
	headerArrival = "X-Arrival-Ns"
	headerVariant = "X-PhotoFinish-Variant"
)

// Config configures the shop.
type Config struct {
	// Window is an artificial pause inserted ONLY in /vuln handlers between
	// the check and the write. 0 means no artificial pause (the race is still
	// real, just narrower). New rejects negative values and values above
	// MaxWindow.
	Window time.Duration
	// Logger receives one line per request (method, path, variant, status,
	// duration) and the details of internal errors. nil discards them.
	Logger *log.Logger
}

// scenarios is the store side of the four race scenarios. vuln.go and
// fixed.go implement it; everything else is shared between the variants.
type scenarios interface {
	// applyCoupon adds a discount for code to the cart owned by owner. It
	// returns errCartNotFound if that cart does not exist (any more), or
	// errCouponApplied.
	applyCoupon(ctx context.Context, cartID, owner, code string, amountCents int64) error
	// transfer moves amountCents from one user to another and returns the
	// sender balance afterwards, or errInsufficientFunds.
	transfer(ctx context.Context, from, to string, amountCents int64) (senderBalance int64, err error)
	// verify2FA spends one attempt, compares code and returns whether it
	// matched and the attempt count afterwards, or errTooManyAttempts.
	verify2FA(ctx context.Context, user, code string) (verified bool, attempts int, err error)
	// redeemGiftCard credits the card value to user and returns the credited
	// amount and the new balance, or errGiftCardNotFound / errGiftCardRedeemed.
	redeemGiftCard(ctx context.Context, user, code string) (credited, balance int64, err error)
}

// variantState is one variant: its store and its scenario implementation.
type variantState struct {
	name Variant
	st   *store
	ops  scenarios
}

// Shop serves the vulnerable and the fixed variant of the demo shop. It is
// safe for concurrent use.
type Shop struct {
	logger   *log.Logger
	variants []*variantState
	handler  http.Handler
}

// New creates a shop with two independent in-memory SQLite stores (one per
// variant), seeded.
func New(cfg Config) (*Shop, error) {
	if cfg.Window < 0 {
		return nil, fmt.Errorf("window must not be negative, got %s", cfg.Window)
	}
	if cfg.Window > MaxWindow {
		return nil, fmt.Errorf("window %s exceeds the maximum of %s", cfg.Window, MaxWindow)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	vst, err := openStore(Vulnerable)
	if err != nil {
		return nil, err
	}
	fst, err := openStore(Fixed)
	if err != nil {
		vst.close()
		return nil, err
	}

	s := &Shop{
		logger: logger,
		variants: []*variantState{
			{name: Vulnerable, st: vst, ops: &vulnScenarios{st: vst, window: cfg.Window}},
			{name: Fixed, st: fst, ops: &fixedScenarios{st: fst}},
		},
	}
	s.handler = s.routes()
	return s, nil
}

// Handler returns the HTTP handler serving both variants.
func (s *Shop) Handler() http.Handler {
	return s.handler
}

// Reset restores the seed state of both variants.
func (s *Shop) Reset() error {
	var errs []error
	for _, v := range s.variants {
		if err := v.st.reset(context.Background()); err != nil {
			errs = append(errs, fmt.Errorf("reset %s: %w", v.name, err))
		}
	}
	return errors.Join(errs...)
}

// Close releases both databases.
func (s *Shop) Close() error {
	var errs []error
	for _, v := range s.variants {
		if err := v.st.close(); err != nil {
			errs = append(errs, fmt.Errorf("close %s: %w", v.name, err))
		}
	}
	return errors.Join(errs...)
}

// routes builds the router for both variants and wraps it with the common
// headers, limits, JSON 404/405 responses and request logging.
func (s *Shop) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	for _, v := range s.variants {
		a := &api{shop: s, v: v}
		p := "/" + string(v.name) + "/api"
		mux.HandleFunc("POST "+p+"/reset", a.handleReset)
		mux.HandleFunc("GET "+p+"/me", a.auth(a.handleMe))
		mux.HandleFunc("POST "+p+"/carts", a.auth(a.handleCreateCart))
		mux.HandleFunc("GET "+p+"/carts/{id}", a.auth(a.handleGetCart))
		mux.HandleFunc("POST "+p+"/carts/{id}/coupons", a.auth(a.handleApplyCoupon))
		mux.HandleFunc("POST "+p+"/transfers", a.auth(a.handleTransfer))
		mux.HandleFunc("POST "+p+"/2fa/verify", a.auth(a.handleVerify2FA))
		mux.HandleFunc("GET "+p+"/2fa/status", a.auth(a.handle2FAStatus))
		mux.HandleFunc("POST "+p+"/giftcards/{code}/redeem", a.auth(a.handleRedeemGiftCard))
	}
	return &frontHandler{shop: s, mux: mux}
}

// frontHandler applies the behavior every response shares.
type frontHandler struct {
	shop *Shop
	mux  *http.ServeMux
}

func (h *frontHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	arrival := time.Now()
	// A non-canonical path (dot segments, repeated slashes) is answered with
	// a JSON 404 instead of the mux's redirect to the cleaned path: that
	// redirect could point into the other variant while this response is
	// labelled with the first, and a 307 replays the method and body there.
	canonical := isCanonical(r)
	variant := ""
	if canonical {
		variant = variantOf(r.URL.Path)
	}

	rec := &statusWriter{ResponseWriter: w}

	// The arrival time is the moment the request is complete. Go starts the
	// handler as soon as the headers arrive, but the race engines hold back
	// the last byte of every request until the release, so the body is read
	// first and the time is taken after it. Read errors (a body over the
	// limit) are replayed to the handler after the bytes that did arrive.
	body, readErr := io.ReadAll(http.MaxBytesReader(rec, r.Body, maxBodyBytes))
	arrivalNs := clock.UnixNano()
	r.Body = &bufferedBody{r: bytes.NewReader(body), err: readErr}

	hdr := w.Header()
	hdr.Set(headerArrival, strconv.FormatInt(arrivalNs, 10))
	hdr.Set("Cache-Control", "no-store")
	if variant != "" {
		hdr.Set(headerVariant, variant)
	}

	if !canonical {
		writeError(rec, http.StatusNotFound, "not found")
	} else if handler, pattern := h.mux.Handler(r); pattern == "" {
		// No route matched: let the mux decide between 404 and 405 (it also
		// computes Allow), then answer in JSON instead of plain text.
		probe := &headerProbe{header: make(http.Header)}
		handler.ServeHTTP(probe, r)
		if probe.status == http.StatusMethodNotAllowed {
			if allow := probe.header.Get("Allow"); allow != "" {
				hdr.Set("Allow", allow)
			}
			writeError(rec, http.StatusMethodNotAllowed, "method not allowed")
		} else {
			writeError(rec, http.StatusNotFound, "not found")
		}
	} else {
		h.mux.ServeHTTP(rec, r)
	}

	if variant == "" {
		variant = "-"
	}
	h.shop.logger.Printf("%s %s variant=%s status=%d dur=%s",
		r.Method, logPath(r), variant, rec.code(), time.Since(arrival).Round(time.Microsecond))
}

// isCanonical reports whether the request path is already in the clean form
// the mux routes on, both percent-encoded and decoded.
func isCanonical(r *http.Request) bool {
	escaped := r.URL.EscapedPath()
	return escaped == cleanPath(escaped) && r.URL.Path == cleanPath(r.URL.Path)
}

// cleanPath returns the canonical form of p the way http.ServeMux computes
// it: rooted, without dot segments or repeated slashes, and keeping a
// trailing slash.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	np := path.Clean(p)
	if strings.HasSuffix(p, "/") && np != "/" {
		np += "/"
	}
	return np
}

// logPath returns the request path for log lines. It stays percent-encoded,
// so a client cannot inject line breaks or terminal escape sequences into
// the log through an encoded path.
func logPath(r *http.Request) string {
	return r.URL.EscapedPath()
}

// variantOf returns the variant named by the first path segment, or "".
func variantOf(path string) string {
	for _, v := range []Variant{Vulnerable, Fixed} {
		if strings.HasPrefix(path, "/"+string(v)+"/") {
			return string(v)
		}
	}
	return ""
}

// statusWriter records the status code for the access log.
// bufferedBody replays a request body that was read ahead, followed by the
// error that ended the read, if any.
type bufferedBody struct {
	r   *bytes.Reader
	err error
}

func (b *bufferedBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if err == io.EOF && b.err != nil {
		return n, b.err
	}
	return n, err
}

func (b *bufferedBody) Close() error { return nil }

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *statusWriter) code() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

// headerProbe captures the status and headers of the mux's built-in 404 and
// 405 handlers and discards their plain-text bodies.
type headerProbe struct {
	header http.Header
	status int
}

func (p *headerProbe) Header() http.Header { return p.header }

func (p *headerProbe) Write(b []byte) (int, error) {
	if p.status == 0 {
		p.status = http.StatusOK
	}
	return len(b), nil
}

func (p *headerProbe) WriteHeader(code int) {
	if p.status == 0 {
		p.status = code
	}
}

// handleIndex serves a plain-text overview of the shop.
func (s *Shop) handleIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, indexText)
}

const indexText = `PhotoFinish demo shop
WARNING: intentionally vulnerable to race conditions - local testing only.

Variants (same routes, independent state):
  /vuln   check-then-act handlers (racy)
  /fixed  atomic handlers

Routes (prefix with /vuln or /fixed):
  POST /api/reset                      restore the seed state (no auth)
  GET  /api/me                         current user and balance
  POST /api/carts                      create a cart (total 8100 cents)
  GET  /api/carts/{id}                 show a cart
  POST /api/carts/{id}/coupons         {"code":"WELCOME10"} apply a coupon once
  POST /api/transfers                  {"to":"bob","amount_cents":6000}
  POST /api/2fa/verify                 {"code":"000000"} at most 3 attempts
  GET  /api/2fa/status                 attempts and checks
  POST /api/giftcards/{code}/redeem    GIFT-ALICE-50 or GIFT-BOB-50, once

Other:
  GET  /healthz

Demo tokens (Authorization: Bearer <token>):
  alice  demo-alice
  bob    demo-bob

Money is integer cents. State lives in memory and is lost on exit.
`

// api serves the routes of one variant.
type api struct {
	shop *Shop
	v    *variantState
}

// authedHandler is a handler that knows the authenticated user.
type authedHandler func(w http.ResponseWriter, r *http.Request, user string)

// auth resolves the bearer token against this variant's users.
func (a *api) auth(next authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			writeError(w, http.StatusUnauthorized, errUnauthorized.Error())
			return
		}
		user, err := a.v.st.userByToken(storeCtx(r), token)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		next(w, r, user)
	}
}

// bearerToken extracts the token from an Authorization header value.
func bearerToken(header string) (string, bool) {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

// storeCtx detaches store operations from client cancellation so that a
// disconnecting client never leaves a multi-statement operation half done.
func storeCtx(r *http.Request) context.Context {
	return context.WithoutCancel(r.Context())
}

func (a *api) handleReset(w http.ResponseWriter, r *http.Request) {
	if !a.decodeOptional(w, r) {
		return
	}
	if err := a.v.st.reset(storeCtx(r)); err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "reset"})
}

func (a *api) handleMe(w http.ResponseWriter, r *http.Request, user string) {
	bal, err := a.v.st.balance(storeCtx(r), user)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		User         string `json:"user"`
		BalanceCents int64  `json:"balance_cents"`
	}{user, bal})
}

func (a *api) handleCreateCart(w http.ResponseWriter, r *http.Request, user string) {
	if !a.decodeOptional(w, r) {
		return
	}
	c, err := a.v.st.createCart(storeCtx(r), user)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (a *api) handleGetCart(w http.ResponseWriter, r *http.Request, user string) {
	c, err := a.v.st.cart(storeCtx(r), r.PathValue("id"), user)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (a *api) handleApplyCoupon(w http.ResponseWriter, r *http.Request, user string) {
	var req struct {
		Code string `json:"code"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	ctx := storeCtx(r)
	c, err := a.v.st.cart(ctx, r.PathValue("id"), user)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	pct, err := a.v.st.couponPercent(ctx, req.Code)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.v.ops.applyCoupon(ctx, c.ID, user, req.Code, c.TotalCents*pct/100); err != nil {
		a.fail(w, r, err)
		return
	}
	c, err = a.v.st.cart(ctx, c.ID, user)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (a *api) handleTransfer(w http.ResponseWriter, r *http.Request, user string) {
	var req struct {
		To          string `json:"to"`
		AmountCents int64  `json:"amount_cents"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	switch {
	case req.AmountCents < 1 || req.AmountCents > maxTransferCents:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("amount_cents must be between 1 and %d", maxTransferCents))
		return
	case req.To == "":
		writeError(w, http.StatusBadRequest, "to is required")
		return
	case req.To == user:
		writeError(w, http.StatusBadRequest, "cannot transfer to yourself")
		return
	}
	ctx := storeCtx(r)
	ok, err := a.v.st.userExists(ctx, req.To)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !ok {
		a.fail(w, r, errRecipientNotFound)
		return
	}
	bal, err := a.v.ops.transfer(ctx, user, req.To, req.AmountCents)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		From         string `json:"from"`
		To           string `json:"to"`
		AmountCents  int64  `json:"amount_cents"`
		BalanceCents int64  `json:"balance_cents"`
	}{user, req.To, req.AmountCents, bal})
}

func (a *api) handleVerify2FA(w http.ResponseWriter, r *http.Request, user string) {
	var req struct {
		Code string `json:"code"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if !isSixDigits(req.Code) {
		writeError(w, http.StatusBadRequest, "code must be 6 digits")
		return
	}
	verified, attempts, err := a.v.ops.verify2FA(storeCtx(r), user, req.Code)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !verified {
		writeJSON(w, http.StatusUnauthorized, struct {
			Error    string `json:"error"`
			Attempts int    `json:"attempts"`
		}{"invalid code", attempts})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "verified"})
}

// isSixDigits reports whether s is exactly six ASCII digits.
func isSixDigits(s string) bool {
	if len(s) != 6 {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func (a *api) handle2FAStatus(w http.ResponseWriter, r *http.Request, user string) {
	attempts, checks, err := a.v.st.twofaStatus(storeCtx(r), user)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Attempts int `json:"attempts"`
		Checks   int `json:"checks"`
		Limit    int `json:"limit"`
	}{attempts, checks, twofaLimit})
}

func (a *api) handleRedeemGiftCard(w http.ResponseWriter, r *http.Request, user string) {
	if !a.decodeOptional(w, r) {
		return
	}
	code := r.PathValue("code")
	credited, bal, err := a.v.ops.redeemGiftCard(storeCtx(r), user, code)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Code          string `json:"code"`
		CreditedCents int64  `json:"credited_cents"`
		BalanceCents  int64  `json:"balance_cents"`
	}{code, credited, bal})
}

// Body decoding errors that are safe to show to clients.
var (
	errEmptyBody    = errors.New("empty body")
	errTrailingData = errors.New("trailing data after JSON body")
)

// decodeJSON reads exactly one JSON value from r into dst, rejecting unknown
// fields and trailing data.
func decodeJSON(r io.Reader, dst any) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if err == io.EOF {
			return errEmptyBody
		}
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return err
		}
		return errTrailingData
	}
	return nil
}

// decode reads a required JSON body into dst. It writes the error response
// and returns false on failure.
func (a *api) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := decodeJSON(r.Body, dst); err != nil {
		a.badBody(w, err)
		return false
	}
	return true
}

// decodeOptional accepts an empty body or an empty JSON object.
func (a *api) decodeOptional(w http.ResponseWriter, r *http.Request) bool {
	body, err := io.ReadAll(r.Body)
	if err == nil && len(bytes.TrimSpace(body)) > 0 {
		err = decodeJSON(bytes.NewReader(body), &struct{}{})
	}
	if err != nil {
		a.badBody(w, err)
		return false
	}
	return true
}

// badBody maps a body read or decode error to 413 or 400.
func (a *api) badBody(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "body too large")
		return
	}
	writeError(w, http.StatusBadRequest, "invalid JSON body: "+publicJSONError(err))
}

// publicJSONError returns a short description of a JSON decode error that
// is safe to show to clients.
func publicJSONError(err error) string {
	var syntax *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntax):
		return "malformed JSON"
	case errors.As(err, &typ):
		return "wrong type for field " + strconv.Quote(typ.Field)
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected end of JSON"
	case errors.Is(err, errEmptyBody), errors.Is(err, errTrailingData):
		return err.Error()
	}
	if msg := err.Error(); strings.HasPrefix(msg, "json: unknown field ") {
		return strings.TrimPrefix(msg, "json: ")
	}
	return "malformed JSON"
}

// statusOf maps business errors to HTTP status codes.
var statusOf = map[error]int{
	errUnauthorized:      http.StatusUnauthorized,
	errCartNotFound:      http.StatusNotFound,
	errCouponNotFound:    http.StatusNotFound,
	errCouponApplied:     http.StatusConflict,
	errRecipientNotFound: http.StatusNotFound,
	errInsufficientFunds: http.StatusConflict,
	errTooManyAttempts:   http.StatusTooManyRequests,
	errGiftCardNotFound:  http.StatusNotFound,
	errGiftCardRedeemed:  http.StatusConflict,
}

// fail writes the response for err. Business errors keep their message;
// anything else is logged and reported as a generic internal error, so
// database details never reach the client.
func (a *api) fail(w http.ResponseWriter, r *http.Request, err error) {
	for known, status := range statusOf {
		if errors.Is(err, known) {
			writeError(w, status, known.Error())
			return
		}
	}
	a.shop.logger.Printf("internal error: %s %s variant=%s: %v", r.Method, logPath(r), a.v.name, err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

// writeJSON writes v as a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeError writes {"error": msg} with the given status.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
