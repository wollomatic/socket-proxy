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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// backend on a unix socket, like the Docker daemon
	socketPath := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := sha256.New()
		if _, err := io.CopyN(h, r.Body, firstPart); err != nil {
			t.Errorf("backend reading first part: %v", err)
			return
		}
		rc := http.NewResponseController(w)
		if err := rc.EnableFullDuplex(); err != nil {
			t.Errorf("backend enabling full duplex: %v", err)
			return
		}
		w.WriteHeader(http.StatusOK)
		if err := rc.Flush(); err != nil {
			t.Errorf("backend flushing response: %v", err)
			return
		}
		n, err := io.Copy(h, r.Body)
		_, _ = fmt.Fprintf(w, "%d %x %v", n+firstPart, h.Sum(nil), err)
	}))
	backend.Listener = l
	backend.Config.ReadHeaderTimeout = 5 * time.Second
	backend.Start()
	t.Cleanup(backend.Close)

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
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}
	socketProxy.Transport = transport
	t.Cleanup(transport.CloseIdleConnections)
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
	uploadDone := make(chan struct{})
	aborted := make(chan struct{})
	// Cancellation must also unblock pipe writes and server-side body reads.
	context.AfterFunc(ctx, func() {
		defer close(aborted)
		_ = pr.CloseWithError(ctx.Err())
		_ = pw.CloseWithError(ctx.Err())
		proxy.CloseClientConnections()
		backend.CloseClientConnections()
	})
	t.Cleanup(func() {
		cancel()
		<-aborted
		<-uploadDone
		// Wait for handlers before restoring the package globals.
		proxy.Close()
		backend.Close()
	})
	go func() {
		defer close(uploadDone)
		if _, err := pw.Write(payload[:firstPart]); err != nil {
			pw.CloseWithError(err)
			return
		}
		select {
		case <-started:
		case <-ctx.Done():
			return
		}
		_, err := pw.Write(payload[firstPart:])
		pw.CloseWithError(err)
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, proxy.URL+"/build", pr)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := proxy.Client().Do(req)
	if err != nil {
		t.Fatalf("response did not start before remaining upload: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected response status: %s", resp.Status)
	}
	close(started)
	got, err := io.ReadAll(resp.Body)
	if err != nil || string(got) != want {
		t.Errorf("backend received %q (response read error: %v), want %q", got, err, want)
	}
}
