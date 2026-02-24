// Package vulnerable contains intentionally insecure Go code for testing purposes.
package vulnerable

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
)

// HardcodedSecret stores a plaintext credential (CWE-798).
const HardcodedSecret = "password123"

// WeakHash uses MD5 for password hashing (CWE-327).
func WeakHash(input string) string {
	h := md5.New()
	h.Write([]byte(input))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// SQLInjection builds a query via string concatenation (CWE-89).
func SQLInjection(db *sql.DB, userInput string) (*sql.Rows, error) {
	query := "SELECT * FROM users WHERE name = '" + userInput + "'"
	return db.Query(query)
}

// CommandInjection passes user input directly to a shell command (CWE-78).
func CommandInjection(userInput string) ([]byte, error) {
	cmd := exec.Command("sh", "-c", "ls "+userInput)
	return cmd.Output()
}

// InsecureRandom uses a non-cryptographic RNG for token generation (CWE-338).
func InsecureRandom() int {
	return rand.Int()
}

// PathTraversal uses user-supplied path without sanitization (CWE-22).
func PathTraversal(userPath string) ([]byte, error) {
	return os.ReadFile("/var/data/" + userPath)
}

// OpenRedirect redirects to a user-controlled URL without validation (CWE-601).
func OpenRedirect(w http.ResponseWriter, r *http.Request) {
	redirectURL := r.URL.Query().Get("url")
	http.Redirect(w, r, redirectURL, http.StatusFound)
}
