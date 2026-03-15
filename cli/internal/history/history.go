package history

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// ScanRecord represents a single scan history entry.
type ScanRecord struct {
	ID        int64     `json:"id"`
	TaskID    string    `json:"task_id"`
	Target    string    `json:"target"`
	Language  string    `json:"language"`
	ScanType  string    `json:"scan_type"`
	Status    string    `json:"status"`
	Critical  int       `json:"critical"`
	High      int       `json:"high"`
	Medium    int       `json:"medium"`
	Low       int       `json:"low"`
	Info      int       `json:"info"`
	Results   string    `json:"results"` // JSON blob
	CreatedAt time.Time `json:"created_at"`
}

// DB wraps the SQLite database connection.
type DB struct {
	conn *sql.DB
}

// dbPath returns the default database path.
func dbPath() string {
	return filepath.Join(os.Getenv("HOME"), ".armur", "history.db")
}

// Open opens or creates the history database.
func Open() (*DB, error) {
	path := dbPath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("failed to create history directory: %w", err)
	}

	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open history database: %w", err)
	}

	if err := migrate(conn); err != nil {
		conn.Close()
		return nil, err
	}

	return &DB{conn: conn}, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// migrate creates the schema if it doesn't exist.
func migrate(conn *sql.DB) error {
	_, err := conn.Exec(`
		CREATE TABLE IF NOT EXISTS scans (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			task_id    TEXT NOT NULL UNIQUE,
			target     TEXT NOT NULL,
			language   TEXT NOT NULL DEFAULT '',
			scan_type  TEXT NOT NULL DEFAULT 'simple',
			status     TEXT NOT NULL DEFAULT 'pending',
			critical   INTEGER NOT NULL DEFAULT 0,
			high       INTEGER NOT NULL DEFAULT 0,
			medium     INTEGER NOT NULL DEFAULT 0,
			low        INTEGER NOT NULL DEFAULT 0,
			info       INTEGER NOT NULL DEFAULT 0,
			results    TEXT NOT NULL DEFAULT '{}',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_scans_task_id ON scans(task_id);
		CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
	`)
	return err
}

// Save inserts or updates a scan record.
func (db *DB) Save(record *ScanRecord) error {
	_, err := db.conn.Exec(`
		INSERT INTO scans (task_id, target, language, scan_type, status, critical, high, medium, low, info, results, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(task_id) DO UPDATE SET
			status = excluded.status,
			critical = excluded.critical,
			high = excluded.high,
			medium = excluded.medium,
			low = excluded.low,
			info = excluded.info,
			results = excluded.results
	`,
		record.TaskID, record.Target, record.Language, record.ScanType,
		record.Status, record.Critical, record.High, record.Medium,
		record.Low, record.Info, record.Results, record.CreatedAt,
	)
	return err
}

// List returns the most recent scan records.
func (db *DB) List(limit int) ([]ScanRecord, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := db.conn.Query(`
		SELECT id, task_id, target, language, scan_type, status, critical, high, medium, low, info, created_at
		FROM scans ORDER BY created_at DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []ScanRecord
	for rows.Next() {
		var r ScanRecord
		if err := rows.Scan(&r.ID, &r.TaskID, &r.Target, &r.Language, &r.ScanType,
			&r.Status, &r.Critical, &r.High, &r.Medium, &r.Low, &r.Info, &r.CreatedAt); err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, nil
}

// Get retrieves a single scan record by task ID.
func (db *DB) Get(taskID string) (*ScanRecord, error) {
	var r ScanRecord
	err := db.conn.QueryRow(`
		SELECT id, task_id, target, language, scan_type, status, critical, high, medium, low, info, results, created_at
		FROM scans WHERE task_id = ?
	`, taskID).Scan(&r.ID, &r.TaskID, &r.Target, &r.Language, &r.ScanType,
		&r.Status, &r.Critical, &r.High, &r.Medium, &r.Low, &r.Info, &r.Results, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// GetByID retrieves a scan record by numeric ID.
func (db *DB) GetByID(id int64) (*ScanRecord, error) {
	var r ScanRecord
	err := db.conn.QueryRow(`
		SELECT id, task_id, target, language, scan_type, status, critical, high, medium, low, info, results, created_at
		FROM scans WHERE id = ?
	`, id).Scan(&r.ID, &r.TaskID, &r.Target, &r.Language, &r.ScanType,
		&r.Status, &r.Critical, &r.High, &r.Medium, &r.Low, &r.Info, &r.Results, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// Clear deletes all scan history.
func (db *DB) Clear() error {
	_, err := db.conn.Exec("DELETE FROM scans")
	return err
}

// Compare returns findings that are new or fixed between two scans.
func (db *DB) Compare(taskID1, taskID2 string) (newFindings, fixedFindings []string, err error) {
	r1, err := db.Get(taskID1)
	if err != nil {
		return nil, nil, fmt.Errorf("scan 1 not found: %w", err)
	}
	r2, err := db.Get(taskID2)
	if err != nil {
		return nil, nil, fmt.Errorf("scan 2 not found: %w", err)
	}

	set1 := extractFindingKeys(r1.Results)
	set2 := extractFindingKeys(r2.Results)

	for key := range set2 {
		if !set1[key] {
			newFindings = append(newFindings, key)
		}
	}
	for key := range set1 {
		if !set2[key] {
			fixedFindings = append(fixedFindings, key)
		}
	}
	return
}

// extractFindingKeys builds a set of unique finding identifiers from JSON results.
func extractFindingKeys(resultsJSON string) map[string]bool {
	keys := map[string]bool{}
	var results map[string]interface{}
	if err := json.Unmarshal([]byte(resultsJSON), &results); err != nil {
		return keys
	}

	for category, data := range results {
		issues, ok := data.([]interface{})
		if !ok {
			continue
		}
		for _, issue := range issues {
			m, ok := issue.(map[string]interface{})
			if !ok {
				continue
			}
			msg := fmt.Sprintf("%v", m["message"])
			path := fmt.Sprintf("%v", m["path"])
			key := fmt.Sprintf("%s:%s:%s", category, path, msg)
			keys[key] = true
		}
	}
	return keys
}
