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
		if !allowPrivate && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
			return fmt.Errorf("%q resolves to non-public/internal address %s (disallowed unless scanners.dast.allow_private is true)", host, ip)
		}
	}
	return nil
}
