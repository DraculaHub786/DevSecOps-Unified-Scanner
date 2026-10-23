//go:build ignore

package tests

import (
	"crypto/des"
	"crypto/md5"
	"database/sql"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

func bad(db *sql.DB, input string, r *http.Request) {
	// ruleid: org-hardcoded-aws-credentials
	_ = "AKIA1234567890ABCDEF"

	// ruleid: org-hardcoded-github-token
	_ = "ghp_1234567890abcdef1234567890abcdef1234"

	// ruleid: org-hardcoded-jwt-secret
	jwt.Sign(input, "super-secret-key")

	// ruleid: org-hardcoded-slack-webhook
	_ = "https://hooks.slack.com/services/T123/B456/7890abcdef"

	// ruleid: org-go-sql-injection-sprintf
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", input))

	// ruleid: org-go-sql-injection-concat
	db.Query("SELECT * FROM users WHERE id = " + input)

	// ruleid: org-go-command-injection-sh
	exec.Command("sh", "-c", input)

	// ruleid: org-go-insecure-skip-verify
	_ = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

	// ruleid: org-go-weak-crypto-md5-sha1
	_ = md5.New()

	// ruleid: org-go-weak-des-cipher
	_, _ = des.NewCipher([]byte("12345678"))

	// ruleid: org-go-insecure-random-number
	_ = rand.Int()

	// ruleid: org-go-path-traversal-open
	_, _ = os.Open(filepath.Join("/tmp", input))

	// ruleid: org-go-bind-all-interfaces
	_, _ = net.Listen("tcp", ":8080")

	// ruleid: org-http-server-timeouts
	_ = http.ListenAndServe(":8080", nil)

	// ruleid: org-bounded-request-body
	_, _ = io.ReadAll(r.Body)

	// ruleid: org-go-cookie-missing-httponly-secure
	_ = &http.Cookie{Name: "session", Value: "123", HttpOnly: false}

	// ruleid: org-go-open-redirect
	http.Redirect(nil, r, r.URL.Query().Get("url"), http.StatusFound)
}

func ok(db *sql.DB, input string) {
	// ok: org-go-sql-injection-sprintf
	db.Query("SELECT * FROM users WHERE id = ?", input)

	// ok: org-go-command-injection-sh
	exec.Command("ls", "-la")
}
