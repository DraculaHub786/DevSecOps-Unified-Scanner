package safety

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// SafeDialContext returns a custom dial context function that checks every resolved IP
// against IsDisallowedIP at dial time, preventing DNS rebinding/TOCTOU attacks.
func SafeDialContext(allowPrivate bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve host %q: %w", host, err)
		}

		for _, ip := range ips {
			if IsDisallowedIP(ip, allowPrivate) {
				return nil, fmt.Errorf("dial blocked: %s resolves to disallowed IP %s", host, ip)
			}
		}

		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
}

// NewSafeHTTPClient returns an http.Client configured with safe dial and redirect protection.
func NewSafeHTTPClient(allowPrivate bool, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		DialContext:           SafeDialContext(allowPrivate),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			host := req.URL.Hostname()
			ips, err := net.LookupIP(host)
			if err != nil {
				return fmt.Errorf("redirect failed: cannot resolve %s", host)
			}
			for _, ip := range ips {
				if IsDisallowedIP(ip, allowPrivate) {
					return fmt.Errorf("redirect blocked: %s points to disallowed IP %s", host, ip)
				}
			}
			return nil
		},
	}
}
