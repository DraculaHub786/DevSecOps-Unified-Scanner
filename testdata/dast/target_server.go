package dast

import (
	"fmt"
	"net/http"
	"net/http/httptest"
)

// NewVulnerableDASTServer starts an in-process HTTP test server with deliberate
// web security misconfigurations for DAST verification testing.
func NewVulnerableDASTServer() *httptest.Server {
	mux := http.NewServeMux()

	// Root endpoint: deliberately missing security headers, wildcard CORS
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		// Deliberately omitted: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options
		fmt.Fprintf(w, "<html><body><h1>Welcome to Vulnerable DAST Target</h1></body></html>")
	})

	// Exposed sensitive .env file
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "DATABASE_URL=postgres://user:supersecretpass@db:5432/prod\nAWS_SECRET_ACCESS_KEY=123456\n")
	})

	// Exposed metrics endpoint
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "# HELP http_requests_total The total number of HTTP requests.\nhttp_requests_total 1027\n")
	})

	return httptest.NewServer(mux)
}
