package main

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"time"
)

func handleSafe(w http.ResponseWriter, r *http.Request) {
	var payload map[string]string
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1048576)).Decode(&payload)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	_ = client
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/safe", handleSafe)

	srv := &http.Server{
		Addr:         ":8443",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	_ = srv.ListenAndServe()
}
