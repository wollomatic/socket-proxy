package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const (
	programName = "socket-proxy"
	version     = "0.1.0"
	programUrl  = "github.com/wollomatic/socket-proxy"
)

const (
	dockerSocketPath        = "/var/run/docker.sock" // path to the docker socket
	tcpServerPort           = "2375"                 // tcp port to listen on
	maxGracefulShutdownTime = 10                     // Maximum time in seconds to wait for the server to shut down gracefully
)

// allowedPaths is a list of path substrings that are allowed to be proxied.
// If the request URL path does not contain any of these substrings, the request is blocked.
var allowedPaths = []string{
	"version",
	"events",
	"containers",
}

var socketProxy *httputil.ReverseProxy

var logAll *bool

// init parses the command line flags.
func init() {
	logAll = flag.Bool("log", false, "log allowed requests (otherwise only blocked requests are logged)")

	flag.Parse()
}

func main() {
	log.Printf("--- Starting %s %s (%s, %s, %s) %s ---\n", programName, version, runtime.GOOS, runtime.GOARCH, runtime.Version(), programUrl)

	// define the reverse proxy
	socketUrlDummy, _ := url.Parse("http://localhost") // dummy URL - we use the unix socket
	socketProxy = httputil.NewSingleHostReverseProxy(socketUrlDummy)
	socketProxy.Transport = &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", dockerSocketPath)
		},
	}

	// start the server in a goroutine
	srv := &http.Server{
		Addr:    ":" + tcpServerPort,
		Handler: http.HandlerFunc(handleGetHeadRequest),
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// Wait for stop signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Try to shut down gracefully
	log.Println("received stop signal - shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), maxGracefulShutdownTime*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("timeout (maybe client still running?): %v", err)
		log.Fatalf("forcing shutdown")
	}
	log.Println(programName, "graceful shutdown complete")
}

// handleGetHeadRequest checks if the request is a GET or HEAD request and sends it to the proxy.
// otherwise it returns a 405 Method Not Allowed error.
func handleGetHeadRequest(w http.ResponseWriter, r *http.Request) {
	// only allow GET and HEAD requests
	if (r.Method != http.MethodGet) && (r.Method != http.MethodHead) {
		fmt.Println("block (bad method)", r.Method, r.URL)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	// check if the request URL path contains any of the allowed paths
	for _, path := range allowedPaths {
		if strings.Contains(r.URL.Path, path) {
			if *logAll {
				log.Println("allow", r.Method, r.URL)
			}
			socketProxy.ServeHTTP(w, r) // proxy the request
			return
		}
	}

	// request URL path does not contain any of the allowed paths, so block the request
	log.Println("block (bad url)", r.Method, r.URL)
	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)

}
