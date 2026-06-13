package remote

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
)

// TestMain relaxes the SSRF dial guard to allow loopback for the duration
// of this package's tests, which fetch from httptest servers bound to
// 127.0.0.1. Production never sets AllowLoopback. Set once before any test
// runs, so there is no data race with the (non-parallel) tests.
func TestMain(m *testing.M) {
	dialPolicy = AddrPolicy{AllowLoopback: true}
	os.Exit(m.Run())
}

// Threat model: an operator- or server-supplied fetch URL must not be able
// to make the agent connect to its own loopback services or the cloud
// instance-metadata endpoint (169.254.169.254). The block list is derived
// from the IP semantics (loopback / link-local / unspecified / multicast),
// NOT from the implementation, so an under-specified guard can't pass by
// matching its own data.

func TestAddrPolicy_BlocksDangerousRanges(t *testing.T) {
	strict := AddrPolicy{} // production default: AllowLoopback false
	blocked := []string{
		"127.0.0.1",        // loopback
		"127.0.0.53",       // loopback (systemd-resolved stub)
		"::1",              // loopback v6
		"::ffff:127.0.0.1", // v4-mapped loopback
		"169.254.169.254",  // AWS/GCP/Azure instance metadata (link-local)
		"169.254.0.1",      // link-local
		"fe80::1",          // link-local v6
		"0.0.0.0",          // unspecified
		"::",               // unspecified v6
		"224.0.0.1",        // multicast
		"ff02::1",          // multicast v6
	}
	for _, s := range blocked {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test bug: %q is not a valid IP", s)
		}
		if !strict.ipBlocked(ip) {
			t.Errorf("ipBlocked(%s) = false, want true (SSRF target)", s)
		}
	}
}

func TestAddrPolicy_AllowsPublicByDefault(t *testing.T) {
	strict := AddrPolicy{}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:2800:220:1::"} {
		ip := net.ParseIP(s)
		if strict.ipBlocked(ip) {
			t.Errorf("ipBlocked(%s) = true, want false (public address)", s)
		}
	}
}

func TestAddrPolicy_PrivateRangesGatedByBlockPrivate(t *testing.T) {
	// Private ranges are allowed by default (internal mirror use), but a
	// strict-egress deployment opts in via BlockPrivate.
	priv := []string{"10.0.0.1", "192.168.1.1", "172.16.5.5", "fd00::1"}
	lenient := AddrPolicy{}
	strict := AddrPolicy{BlockPrivate: true}
	for _, s := range priv {
		ip := net.ParseIP(s)
		if lenient.ipBlocked(ip) {
			t.Errorf("default ipBlocked(%s) = true, want false", s)
		}
		if !strict.ipBlocked(ip) {
			t.Errorf("BlockPrivate ipBlocked(%s) = false, want true", s)
		}
	}
}

func TestAddrPolicy_AllowLoopbackKnob(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	if !(AddrPolicy{}).ipBlocked(ip) {
		t.Error("default policy must block loopback")
	}
	if (AddrPolicy{AllowLoopback: true}).ipBlocked(ip) {
		t.Error("AllowLoopback policy must permit loopback")
	}
}

func TestAddrPolicy_NilIPFailsClosed(t *testing.T) {
	if !(AddrPolicy{}).ipBlocked(nil) {
		t.Error("ipBlocked(nil) = false, want true (fail closed)")
	}
}

func TestControlConn_RejectsBlockedDialAddress(t *testing.T) {
	strict := AddrPolicy{}
	if err := strict.controlConn("tcp", "169.254.169.254:80", nil); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("controlConn(metadata) = %v, want ErrBlockedAddress", err)
	}
	if err := strict.controlConn("tcp", "127.0.0.1:8080", nil); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("controlConn(loopback) = %v, want ErrBlockedAddress", err)
	}
	// A public address passes.
	if err := strict.controlConn("tcp", "93.184.216.34:443", nil); err != nil {
		t.Errorf("controlConn(public) = %v, want nil", err)
	}
	// A non-IP / malformed dial address fails closed.
	if err := strict.controlConn("tcp", "not-an-address", nil); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("controlConn(malformed) = %v, want ErrBlockedAddress", err)
	}
}

func TestRedirectPolicy_BlocksNonHTTPSchemesAndCapsHops(t *testing.T) {
	mk := func(scheme string) *http.Request {
		return &http.Request{URL: &url.URL{Scheme: scheme, Host: "example.test"}}
	}
	if err := redirectPolicy(mk("file"), nil); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("redirect to file:// = %v, want ErrBlockedAddress", err)
	}
	if err := redirectPolicy(mk("gopher"), nil); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("redirect to gopher:// = %v, want ErrBlockedAddress", err)
	}
	if err := redirectPolicy(mk("https"), nil); err != nil {
		t.Errorf("redirect to https:// = %v, want nil", err)
	}
	// Hop cap: 10 prior requests must stop the chain.
	via := make([]*http.Request, 10)
	if err := redirectPolicy(mk("https"), via); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("11th redirect = %v, want ErrBlockedAddress", err)
	}
}

func TestGuardedHTTPClient_HasGuardWiring(t *testing.T) {
	c := guardedHTTPClient(0, AddrPolicy{})
	if c.CheckRedirect == nil {
		t.Error("guarded client must set CheckRedirect")
	}
	if c.Transport == nil {
		t.Error("guarded client must install a custom Transport (dial guard)")
	}
}
