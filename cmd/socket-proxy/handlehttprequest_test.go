package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/wollomatic/socket-proxy/internal/config"
)

// TestStreamedRequestBodyAfterResponseStart mimics POST /build since Docker Engine 29.5:
// dockerd starts writing the response while it is still reading the build context
// from the request body, so the proxy has to keep forwarding the body after the
// response has begun.
func TestStreamedRequestBodyAfterResponseStart(t *testing.T) {
	const (
		firstPart = 64 << 10 // sent before the response starts
		total     = 4 << 20  // well above net/http's 256 KiB post-handler drain limit
	)

	// backend on a unix socket, like the Docker daemon
	socketPath := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	backend := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rc := http.NewResponseController(w)
			_ = rc.EnableFullDuplex()
			w.WriteHeader(http.StatusOK)
			_ = rc.Flush()
			h := sha256.New()
			n, err := io.Copy(h, r.Body)
			_, _ = fmt.Fprintf(w, "%d %x %v", n, h.Sum(nil), err)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = backend.Serve(l) }()
	t.Cleanup(func() { _ = backend.Close() })

	prevCfg, prevProxy := cfg, socketProxy
	t.Cleanup(func() { cfg, socketProxy = prevCfg, prevProxy })
	cfg = &config.Config{
		AllowFrom: []string{"127.0.0.1/32"},
		AllowLists: &config.AllowListRegistry{Default: config.AllowList{
			AllowedRequests: map[string][]*regexp.Regexp{http.MethodPost: {regexp.MustCompile(`^/build$`)}},
		}},
		SocketPath: socketPath,
	}
	// same setup as in main()
	socketURLDummy, _ := url.Parse("http://localhost")
	socketProxy = httputil.NewSingleHostReverseProxy(socketURLDummy)
	socketProxy.Transport = &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}
	proxy := httptest.NewServer(http.HandlerFunc(handleHTTPRequest))
	t.Cleanup(proxy.Close)

	payload := make([]byte, total)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	want := fmt.Sprintf("%d %x <nil>", total, sha256.Sum256(payload))

	// send the rest of the body only once the response has started
	pr, pw := io.Pipe()
	started := make(chan struct{})
	go func() {
		if _, err := pw.Write(payload[:firstPart]); err != nil {
			pw.CloseWithError(err)
			return
		}
		select {
		case <-started:
		case <-time.After(3 * time.Second): // response never started; send anyway so the test ends
		}
		_, err := pw.Write(payload[firstPart:])
		pw.CloseWithError(err)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, proxy.URL+"/build", pr)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := proxy.Client().Do(req)
	close(started)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil || string(got) != want {
		t.Errorf("backend received %q (response read error: %v), want %q", got, err, want)
	}
}
