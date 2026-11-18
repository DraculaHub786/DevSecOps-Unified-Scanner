package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

// SQL injection via Sprintf
func handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	q := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
	db.Query(q)
}

// Command injection
func run(r *http.Request) {
	cmd := r.FormValue("c")
	exec.Command("sh", "-c", cmd).Run()
}

// Weak crypto
func hashIt(s []byte) []byte {
	h := md5.New()
	h.Write(s)
	return h.Sum(nil)
}

// Hardcoded credential
const DBPassword = "SuperSecretPassword123!"
