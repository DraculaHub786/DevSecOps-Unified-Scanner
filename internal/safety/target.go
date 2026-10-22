package safety

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
)

// ValidateTarget enforces legal authorization and network safety boundaries for DAST scanning.
// Rejects unauthorized targets, non-allowlisted domains, and private/loopback/cloud metadata IPs.
func ValidateTarget(raw string, allowlist []string, authorized, allowPrivate bool) error {
	if !authorized {
		return errors.New("DAST requires explicit authorization flag --i-have-authorization; scan only systems you own or have written permission to test")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fmt.Errorf("invalid target URL %q (must be http or https)", raw)
	}
	host := u.Hostname()
	if !slices.Contains(allowlist, host) {
		return fmt.Errorf("host %q is not declared in scanners.dast.allowlist", host)
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("cannot resolve hostname %q", host)
	}
	for _, ip := range ips {
		if IsDisallowedIP(ip, allowPrivate) {
			return fmt.Errorf("%q resolves to non-public/internal address %s (disallowed unless scanners.dast.allow_private is true)", host, ip)
		}
	}
	return nil
}

// IsDisallowedIP tests if an IP is private, loopback, link-local, unspecified, or cloud metadata.
func IsDisallowedIP(ip net.IP, allowPrivate bool) bool {
	if allowPrivate {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	// AWS, GCP, Azure, DigitalOcean instance metadata service IP
	if ip.String() == "169.254.169.254" {
		return true
	}
	return false
}
