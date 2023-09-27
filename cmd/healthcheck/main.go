package main

import (
	"log"
	"net/http"
)

// main does a health check against the socket-proxy server
// if the health check fails, the program exits with a non-zero exit code and logs an error
// if the health check succeeds, the program exits with a zero exit code
// socket-proxy must be started with the -allowhealthcheck flag
func main() {
	resp, err := http.Head("http://localhost:55555/health")
	if err != nil {
		log.Fatal("error doing health check: ", err)
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatal("health check failed, got status: ", resp.StatusCode)
	}
}
