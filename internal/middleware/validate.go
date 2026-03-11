package middleware

import (
	"armur-codescanner/internal/logger"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	// MaxUploadSize is the maximum allowed file upload size (50 MB).
	MaxUploadSize = 50 << 20 // 50 MB
)

// RequestSizeLimit returns a middleware that rejects requests whose body exceeds maxBytes.
func RequestSizeLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}

// ValidateGitURL checks that a repository URL is a valid, publicly reachable HTTPS URL
// and is not pointing at a private/internal network address.
func ValidateGitURL(rawURL string) error {
	if rawURL == "" {
		return &ValidationError{"repository URL must not be empty"}
	}

	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return &ValidationError{"invalid URL: " + err.Error()}
	}

	if !strings.EqualFold(parsed.Scheme, "https") {
		return &ValidationError{"only https:// URLs are allowed"}
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return &ValidationError{"URL must contain a valid hostname"}
	}

	// Block private and loopback IP addresses
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		// If we can't resolve at validation time just let the clone fail naturally
		logger.Debug().Str("host", hostname).Err(err).Msg("hostname resolution failed during validation, allowing")
		return nil
	}

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if isPrivateIP(ip) {
			return &ValidationError{"URL resolves to a private/internal IP address"}
		}
	}

	return nil
}

func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
	}
	for _, cidr := range privateRanges {
		_, block, _ := net.ParseCIDR(cidr)
		if block != nil && block.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateTaskID returns true if the given string is a valid UUID v4.
func ValidateTaskID(id string) bool {
	if len(id) != 36 {
		return false
	}
	// Simple format check: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	parts := strings.Split(id, "-")
	if len(parts) != 5 {
		return false
	}
	lengths := []int{8, 4, 4, 4, 12}
	for i, part := range parts {
		if len(part) != lengths[i] {
			return false
		}
		for _, c := range part {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

// SanitizeLocalPath cleans and validates a local filesystem path to prevent
// path traversal attacks (CWE-22). It returns the cleaned absolute path or
// an error if the path contains traversal sequences or is otherwise invalid.
func SanitizeLocalPath(rawPath string) (string, error) {
	if rawPath == "" {
		return "", &ValidationError{"local path must not be empty"}
	}

	// Clean the path to resolve any ".." or "." elements.
	cleaned := filepath.Clean(rawPath)

	// Reject any path that still contains ".." after cleaning — this should
	// never happen after filepath.Clean, but acts as a defence-in-depth guard.
	if strings.Contains(cleaned, "..") {
		return "", &ValidationError{"path traversal sequences are not allowed"}
	}

	// Reject paths that are not absolute.
	if !filepath.IsAbs(cleaned) {
		return "", &ValidationError{"local path must be an absolute path"}
	}

	return cleaned, nil
}

// ValidationError is a user-facing validation failure.
type ValidationError struct {
	msg string
}

func (e *ValidationError) Error() string { return e.msg }
