package main

import (
	"crypto/tls"
	"io"
	"net/http"
)

func handleUpload(w http.ResponseWriter, r *http.Request) {
	// Resilience: Unbounded memory allocation
	body, _ := io.ReadAll(r.Body)
	w.Write(body)
}

func main() {
	// SAST: Insecure TLS configuration
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	_ = &http.Client{Transport: tr}

	// Resilience: default ListenAndServe with no timeouts
	http.HandleFunc("/upload", handleUpload)
	http.ListenAndServe(":8080", nil)
}
