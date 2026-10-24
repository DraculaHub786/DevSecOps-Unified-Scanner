package clean

import (
	"database/sql"
	"net/http"
	"time"
)

func SafeQuery(db *sql.DB, id int) (*sql.Rows, error) {
	return db.Query("SELECT id, name FROM users WHERE id = ?", id)
}

func NewSafeClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}
