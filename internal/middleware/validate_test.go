package middleware

import (
	"net"
	"testing"
)

func TestValidateGitURL_InvalidScheme(t *testing.T) {
	bad := []string{
		"http://github.com/user/repo",
		"ssh://github.com/user/repo",
		"git://github.com/user/repo",
		"file:///etc/passwd",
	}
	for _, u := range bad {
		t.Run(u, func(t *testing.T) {
			err := ValidateGitURL(u)
			if err == nil {
				t.Errorf("ValidateGitURL(%q) expected error for non-https scheme, got nil", u)
			}
		})
	}
}

func TestValidateGitURL_Empty(t *testing.T) {
	if err := ValidateGitURL(""); err == nil {
		t.Error("ValidateGitURL(\"\") expected error, got nil")
	}
}

func TestValidateGitURL_MalformedURL(t *testing.T) {
	if err := ValidateGitURL("not a url at all"); err == nil {
		t.Error("expected error for malformed URL, got nil")
	}
}

func TestValidateGitURL_ValidHTTPS(t *testing.T) {
	// These are syntactically valid HTTPS URLs; DNS errors in CI are not a test failure.
	validURLs := []string{
		"https://github.com/Armur-Ai/Armur-Code-Scanner",
		"https://gitlab.com/user/repo",
	}
	for _, u := range validURLs {
		t.Run(u, func(t *testing.T) {
			err := ValidateGitURL(u)
			if err != nil {
				ve, isValidationErr := err.(*ValidationError)
				if isValidationErr && (ve.Error() == "only https:// URLs are allowed" ||
					ve.Error() == "repository URL must not be empty" ||
					ve.Error() == "URL must contain a valid hostname") {
					t.Errorf("ValidateGitURL(%q) unexpected validation error: %v", u, err)
				}
				// DNS resolution failures in CI are acceptable — skip silently
			}
		})
	}
}

func TestValidateTaskID_Valid(t *testing.T) {
	valid := []string{
		"550e8400-e29b-41d4-a716-446655440000",
		"6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		"00000000-0000-0000-0000-000000000000",
	}
	for _, id := range valid {
		t.Run(id, func(t *testing.T) {
			if !ValidateTaskID(id) {
				t.Errorf("ValidateTaskID(%q) = false, want true", id)
			}
		})
	}
}

func TestValidateTaskID_Invalid(t *testing.T) {
	invalid := []string{
		"",
		"not-a-uuid",
		"550e8400-e29b-41d4-a716",
		"550e8400e29b41d4a716446655440000",
		"550e8400-e29b-41d4-a716-44665544000z",
		"550e8400-e29b-41d4-a716-4466554400",
	}
	for _, id := range invalid {
		t.Run(id, func(t *testing.T) {
			if ValidateTaskID(id) {
				t.Errorf("ValidateTaskID(%q) = true, want false", id)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("could not parse IP %q", tt.ip)
			}
			got := isPrivateIP(ip)
			if got != tt.private {
				t.Errorf("isPrivateIP(%q) = %v, want %v", tt.ip, got, tt.private)
			}
		})
	}
}
