package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/TroubieD3v/photofinish/internal/demo"
)

// demoStartTimeout bounds how long StartDemo waits for the listener.
const demoStartTimeout = 10 * time.Second

// demoStatus is the demo part of /api/info and the answer of
// /api/demo/start and /api/demo/stop.
type demoStatus struct {
	Running bool `json:"running"`
	// URL is where the shop listens, or will listen once started.
	URL string `json:"url"`
}

// demoShop runs the in-process demo shop, as "photofinish demo" does.
type demoShop struct {
	addr   string
	window time.Duration

	mu     sync.Mutex
	bound  string // listen address while running
	shop   *demo.Shop
	cancel context.CancelFunc
	done   chan error
}

func newDemoShop(addr string, window time.Duration) *demoShop {
	return &demoShop{addr: addr, window: window}
}

// status reports whether the shop runs and its URL.
func (d *demoShop) status() demoStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.shop != nil {
		return demoStatus{Running: true, URL: "https://" + d.bound}
	}
	return demoStatus{URL: "https://" + d.addr}
}

// start starts the shop unless it runs already, and waits until it listens.
func (d *demoShop) start() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.shop != nil {
		return nil
	}
	// No request log: the shop shares the terminal of the server.
	shop, err := demo.New(demo.Config{Window: d.window})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- demo.Serve(ctx, d.addr, shop, func(addr, _ string) { ready <- addr })
	}()
	select {
	case addr := <-ready:
		d.shop, d.cancel, d.done, d.bound = shop, cancel, done, addr
		return nil
	case err := <-done:
		cancel()
		shop.Close()
		if err == nil {
			err = errors.New("the demo shop stopped at once")
		}
		return fmt.Errorf("start the demo shop on %s: %w", d.addr, err)
	case <-time.After(demoStartTimeout):
		cancel()
		<-done
		shop.Close()
		return fmt.Errorf("the demo shop did not start within %s", demoStartTimeout)
	}
}

// stop stops the shop if it runs and waits for it to shut down.
func (d *demoShop) stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.shop == nil {
		return nil
	}
	d.cancel()
	err := <-d.done
	err = errors.Join(err, d.shop.Close())
	d.shop, d.cancel, d.done, d.bound = nil, nil, nil, ""
	return err
}

// StartDemo starts the in-process demo shop (serve --demo).
func (s *Server) StartDemo() error { return s.demo.start() }

// DemoURL returns the URL of the demo shop.
func (s *Server) DemoURL() string { return s.demo.status().URL }

func (s *Server) demoStart(w http.ResponseWriter, r *http.Request) {
	if err := s.demo.start(); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, s.demo.status())
}

func (s *Server) demoStop(w http.ResponseWriter, r *http.Request) {
	if err := s.demo.stop(); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, s.demo.status())
}

// parseTargetURL accepts an absolute http or https URL with a host, as the
// probe command does.
func parseTargetURL(s string) (*url.URL, error) {
	if s == "" {
		return nil, errors.New("the body needs \"url\"")
	}
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

// insecureTLS skips certificate verification for a probe that asks for it.
func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} // requested by the user: self-signed lab target
}
