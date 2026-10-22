package safety

import (
	"context"
	"testing"
	"time"
)

func TestSafeDialBlocksDisallowed(t *testing.T) {
	dialFunc := SafeDialContext(false)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 127.0.0.1 is loopback and must be rejected
	_, err := dialFunc(ctx, "tcp", "127.0.0.1:80")
	if err == nil {
		t.Errorf("expected error connecting to loopback 127.0.0.1 when allowPrivate is false, got nil")
	}

	// 169.254.169.254 is metadata IP and must be rejected
	_, err = dialFunc(ctx, "tcp", "169.254.169.254:80")
	if err == nil {
		t.Errorf("expected error connecting to metadata IP 169.254.169.254, got nil")
	}
}

func TestNewSafeHTTPClient(t *testing.T) {
	client := NewSafeHTTPClient(false, 3*time.Second)
	if client == nil || client.Transport == nil {
		t.Fatalf("expected non-nil safe client and transport")
	}

	// Attempting request to loopback should fail safely at dial
	_, err := client.Get("http://127.0.0.1:9999/test")
	if err == nil {
		t.Errorf("expected get on loopback to fail, got nil")
	}
}
