package safety

import (
	"strings"
	"testing"
)

func TestValidateTarget(t *testing.T) {
	tests := []struct {
		name         string
		rawURL       string
		allowlist    []string
		authorized   bool
		allowPrivate bool
		wantErrMsg   string
	}{
		{
			name:         "unauthorized flag fails",
			rawURL:       "https://example.com",
			allowlist:    []string{"example.com"},
			authorized:   false,
			allowPrivate: false,
			wantErrMsg:   "requires explicit authorization flag",
		},
		{
			name:         "invalid scheme fails",
			rawURL:       "ftp://example.com",
			allowlist:    []string{"example.com"},
			authorized:   true,
			allowPrivate: false,
			wantErrMsg:   "invalid target URL",
		},
		{
			name:         "host not in allowlist fails",
			rawURL:       "https://notallowed.com",
			allowlist:    []string{"example.com"},
			authorized:   true,
			allowPrivate: false,
			wantErrMsg:   "is not declared in scanners.dast.allowlist",
		},
		{
			name:         "localhost blocked when allowPrivate is false",
			rawURL:       "http://127.0.0.1:8080",
			allowlist:    []string{"127.0.0.1"},
			authorized:   true,
			allowPrivate: false,
			wantErrMsg:   "resolves to non-public/internal address",
		},
		{
			name:         "localhost allowed when allowPrivate is true",
			rawURL:       "http://127.0.0.1:8080",
			allowlist:    []string{"127.0.0.1"},
			authorized:   true,
			allowPrivate: true,
			wantErrMsg:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTarget(tt.rawURL, tt.allowlist, tt.authorized, tt.allowPrivate)
			if tt.wantErrMsg == "" {
				if err != nil {
					t.Errorf("ValidateTarget() unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("ValidateTarget() expected error containing %q, got nil", tt.wantErrMsg)
				}
				if !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Errorf("ValidateTarget() error = %v, want substring %q", err, tt.wantErrMsg)
				}
			}
		})
	}
}
