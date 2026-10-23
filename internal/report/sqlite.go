package report

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
	_ "modernc.org/sqlite"
)

// ScanHistoryRecord represents a past scan entry stored in SQLite.
type ScanHistoryRecord struct {
	ID            int64     `json:"id"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	CommitSHA     string    `json:"commit_sha"`
	TotalFindings int       `json:"total_findings"`
	CriticalCount int       `json:"critical_count"`
	HighCount     int       `json:"high_count"`
}

// DiffResult shows delta between two scan records.
type DiffResult struct {
	ScanA     int64                  `json:"scan_a"`
	ScanB     int64                  `json:"scan_b"`
	New       []orchestrator.Finding `json:"new"`
	Fixed     []orchestrator.Finding `json:"fixed"`
	Unchanged []orchestrator.Finding `json:"unchanged"`
}

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

// initDB creates all tables and runs schema migrations if not yet present.
func (s *SQLiteStore) initDB(db *sql.DB) error {
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
	  scan_id INTEGER,
	  id TEXT,
	  fingerprint TEXT,
	  engine TEXT DEFAULT 'embedded',
	  category TEXT,
	  severity TEXT,
	  file TEXT,
	  line_start INTEGER,
	  risk_score REAL,
	  FOREIGN KEY(scan_id) REFERENCES scans(id)
	);
	CREATE TABLE IF NOT EXISTS baselines (
	  id INTEGER PRIMARY KEY AUTOINCREMENT,
	  created_at TIMESTAMP,
	  fingerprint TEXT UNIQUE,
	  rule TEXT,
	  file TEXT
	);
	`
	if _, err := db.Exec(schema); err != nil {
		return err
	}

	// Schema migration for old history.db tables
	_, _ = db.Exec("ALTER TABLE findings ADD COLUMN engine TEXT DEFAULT 'embedded'")
	_, _ = db.Exec("ALTER TABLE findings ADD COLUMN status TEXT DEFAULT 'open'")
	return nil
}

// RecordScan records the scan metadata and its findings into SQLite with schema migrations.
func (s *SQLiteStore) RecordScan(result *orchestrator.ScanResult, commitSHA string) error {
	db, err := sql.Open("sqlite", s.dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := s.initDB(db); err != nil {
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
		INSERT OR REPLACE INTO findings (id, scan_id, fingerprint, engine, category, severity, file, line_start, risk_score, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, f := range result.Findings {
		eng := f.Engine
		if eng == "" {
			eng = orchestrator.EngineEmbedded
		}
		if _, err := stmt.Exec(f.ID, scanID, f.Fingerprint, eng, f.Category, f.Severity, f.File, f.LineStart, f.RiskScore); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// ListScans returns recent historical scan summaries.
func (s *SQLiteStore) ListScans() ([]ScanHistoryRecord, error) {
	db, err := sql.Open("sqlite", s.dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`SELECT id, started_at, finished_at, commit_sha, total_findings, critical_count, high_count FROM scans ORDER BY id DESC LIMIT 25`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []ScanHistoryRecord
	for rows.Next() {
		var r ScanHistoryRecord
		var startStr, finStr string
		if err := rows.Scan(&r.ID, &startStr, &finStr, &r.CommitSHA, &r.TotalFindings, &r.CriticalCount, &r.HighCount); err != nil {
			continue
		}
		r.StartedAt, _ = time.Parse(time.RFC3339, startStr)
		r.FinishedAt, _ = time.Parse(time.RFC3339, finStr)
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

// CompareScans compares findings from two historical scan IDs.
func (s *SQLiteStore) CompareScans(scanA, scanB int64) (*DiffResult, error) {
	db, err := sql.Open("sqlite", s.dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	getFindings := func(scanID int64) (map[string]orchestrator.Finding, error) {
		rows, err := db.Query(`SELECT id, fingerprint, engine, category, severity, file, line_start, risk_score FROM findings WHERE scan_id = ?`, scanID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		res := make(map[string]orchestrator.Finding)
		for rows.Next() {
			var f orchestrator.Finding
			if err := rows.Scan(&f.ID, &f.Fingerprint, &f.Engine, &f.Category, &f.Severity, &f.File, &f.LineStart, &f.RiskScore); err == nil {
				res[f.Fingerprint] = f
			}
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return res, nil
	}

	findingsA, err := getFindings(scanA)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch scan %d: %w", scanA, err)
	}
	findingsB, err := getFindings(scanB)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch scan %d: %w", scanB, err)
	}

	diff := &DiffResult{
		ScanA:     scanA,
		ScanB:     scanB,
		New:       make([]orchestrator.Finding, 0),
		Fixed:     make([]orchestrator.Finding, 0),
		Unchanged: make([]orchestrator.Finding, 0),
	}

	for fp, fB := range findingsB {
		if _, exists := findingsA[fp]; exists {
			diff.Unchanged = append(diff.Unchanged, fB)
		} else {
			diff.New = append(diff.New, fB)
		}
	}

	for fp, fA := range findingsA {
		if _, exists := findingsB[fp]; !exists {
			diff.Fixed = append(diff.Fixed, fA)
		}
	}

	return diff, nil
}

// SaveBaseline stores baseline fingerprints into the SQLite database.
func (s *SQLiteStore) SaveBaseline(fingerprints []string) error {
	db, err := sql.Open("sqlite", s.dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := s.initDB(db); err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO baselines (created_at, fingerprint) VALUES (?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now().UTC().Format(time.RFC3339)
	for _, fp := range fingerprints {
		if _, err := stmt.Exec(now, fp); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetBaseline retrieves all baseline fingerprints from the SQLite database.
func (s *SQLiteStore) GetBaseline() ([]string, error) {
	db, err := sql.Open("sqlite", s.dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	if err := s.initDB(db); err != nil {
		return nil, err
	}

	rows, err := db.Query(`SELECT DISTINCT fingerprint FROM baselines`)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var fps []string
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err == nil && fp != "" {
			fps = append(fps, fp)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return fps, nil
}
