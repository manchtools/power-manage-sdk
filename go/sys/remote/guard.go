package remote

import (
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// AddrPolicy decides which resolved IPs an outbound fetch may dial. It is
// the SSRF guard for the HTTP and S3 sources: an operator- or
// server-supplied URL must not be able to make the agent connect to its
// own loopback services or the cloud instance-metadata endpoint.
type AddrPolicy struct {
	// BlockPrivate additionally refuses RFC1918 / RFC4193 (ULA) ranges.
	// Off by default because an agent on a corporate LAN legitimately
	// pulls from an internal mirror (10/8, 192.168/16, fd00::/8);
	// deployments that want strict egress opt in.
	BlockPrivate bool

	// AllowLoopback permits loopback destinations. Off by default —
	// loopback is an SSRF pivot to device-local admin services. A
	// deployment that fronts fetches through a local caching proxy can
	// opt in. (The package's own tests set this to reach httptest
	// servers; production must not.)
	AllowLoopback bool
}

// dialPolicy is the SSRF policy installed on every fetch client built by
// defaultHTTPClient. Production leaves it at the strict zero value; the
// package's tests relax it (AllowLoopback) in TestMain to reach loopback
// httptest servers.
var dialPolicy = AddrPolicy{}

// ipBlocked reports whether ip must never be dialed for an outbound fetch.
// The blocked set is the classic SSRF target list: loopback (device-local
// services), link-local (169.254.0.0/16 — cloud instance metadata — and
// the IPv6 fe80::/10 equivalent), unspecified (0.0.0.0 / ::), and
// multicast. A nil ip fails closed.
func (p AddrPolicy) ipBlocked(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() {
		return !p.AllowLoopback
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if p.BlockPrivate && ip.IsPrivate() {
		return true
	}
	return false
}

// controlConn is a net.Dialer.Control hook. The runtime calls it after
// name resolution with the concrete IP about to be dialed, so it guards
// the initial connection, every redirect hop, AND defeats DNS rebinding
// (the IP is re-checked at connect time, not at URL-parse time). The
// address is always "ip:port" at this point.
//
// Limitation: when an HTTP(S) proxy is configured via the environment the
// dialer connects to the proxy, not the origin, so this check sees the
// proxy IP. Strict-egress deployments that need the guard should not route
// fetches through an untrusted proxy.
func (p AddrPolicy) controlConn(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: cannot parse dial address %q: %v", ErrBlockedAddress, address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: dial address %q is not a literal IP", ErrBlockedAddress, address)
	}
	if p.ipBlocked(ip) {
		return fmt.Errorf("%w: refusing to dial %s", ErrBlockedAddress, ip)
	}
	return nil
}

// redirectPolicy re-validates every redirect hop: the scheme must stay
// http/https (so a 302 can't pivot to file://, gopher://, etc.) and the
// chain is capped at 10 hops. The destination host/IP is enforced
// separately at dial time by controlConn, which also covers rebinding.
func redirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("%w: stopped after 10 redirects", ErrBlockedAddress)
	}
	if s := req.URL.Scheme; s != "https" && s != "http" {
		return fmt.Errorf("%w: redirect to unsupported scheme %q", ErrBlockedAddress, s)
	}
	return nil
}

// guardedHTTPClient builds an *http.Client whose transport refuses to dial
// any IP the policy blocks and whose redirect handler re-validates each
// hop's scheme. A zero timeout means no client-level timeout (callers that
// want one pass it explicitly).
func guardedHTTPClient(timeout time.Duration, policy AddrPolicy) *http.Client {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   policy.controlConn,
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: redirectPolicy,
	}
}

// defaultHTTPClient is the fetch client used by the HTTP and S3 sources:
// a 30-minute ceiling (large artefacts over slow links) plus the SSRF dial
// guard and redirect re-validation.
func defaultHTTPClient() *http.Client {
	return guardedHTTPClient(30*time.Minute, dialPolicy)
}
