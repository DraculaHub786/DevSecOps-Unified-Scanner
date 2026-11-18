package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

// TP: weak cryptography (CWE-328)
func hashPassword(password string) []byte {
	sum := md5.Sum([]byte(password))
	return sum[:]
}

// TP: SQL injection via Sprintf (CWE-89)
func lookupUser(db *sql.DB, r *http.Request) (*sql.Row, error) {
	userID := r.URL.Query().Get("id")
	query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userID)
	return db.QueryRow(query), nil
}

// TP: command injection via sh -c (CWE-78)
func runTool(r *http.Request) error {
	name := r.FormValue("tool")
	return exec.Command("sh", "-c", "tool "+name).Run()
}

// TP: path traversal (CWE-22)
func readUpload(r *http.Request) ([]byte, error) {
	filename := r.URL.Query().Get("file")
	return os.ReadFile(filename)
}

// Negative: parameterised query, no string interpolation
func lookupUserSafe(db *sql.DB, userID int) (*sql.Row, error) {
	return db.QueryRow("SELECT * FROM users WHERE id = $1", userID), nil
}
