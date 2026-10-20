package report

import (
	"database/sql"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
	"github.com/sentinel-dev/sentinel/internal/orchestrator"
)

// SQLiteStore saves scan records and findings for local historical tracking.
type SQLiteStore struct {
	dbPath string
}

func NewSQLiteStore(repoPath string) (*SQLiteStore, error) {
	dir := filepath.Join(repoPath, ".sentinel")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(dir, "history.db")
	return &SQLiteStore{dbPath: dbPath}, nil
}

// RecordScan records the scan metadata and its findings into SQLite.
func (s *SQLiteStore) RecordScan(result *orchestrator.ScanResult, commitSHA string) error {
	db, err := sql.Open("sqlite", s.dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	schema := `
	CREATE TABLE IF NOT EXISTS scans (
	  id INTEGER PRIMARY KEY AUTOINCREMENT,
	  started_at TIMESTAMP,
	  finished_at TIMESTAMP,
	  commit_sha TEXT,
	  total_findings INTEGER,
	  critical_count INTEGER,
	  high_count INTEGER
	);
	CREATE TABLE IF NOT EXISTS findings (
	  id TEXT PRIMARY KEY,
	  scan_id INTEGER,
	  fingerprint TEXT,
	  category TEXT,
	  severity TEXT,
	  file TEXT,
	  line_start INTEGER,
	  risk_score REAL,
	  status TEXT,
	  FOREIGN KEY(scan_id) REFERENCES scans(id)
	);
	`
	if _, err := db.Exec(schema); err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.Exec(`
		INSERT INTO scans (started_at, finished_at, commit_sha, total_findings, critical_count, high_count)
		VALUES (?, ?, ?, ?, ?, ?)
	`, result.StartedAt.Format(time.RFC3339), result.FinishedAt.Format(time.RFC3339), commitSHA, result.Summary.Total, result.Summary.Critical, result.Summary.High)
	if err != nil {
		return err
	}

	scanID, err := res.LastInsertId()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO findings (id, scan_id, fingerprint, category, severity, file, line_start, risk_score, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open')
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, f := range result.Findings {
		if _, err := stmt.Exec(f.ID, scanID, f.Fingerprint, f.Category, f.Severity, f.File, f.LineStart, f.RiskScore); err != nil {
			return err
		}
	}

	return tx.Commit()
}
