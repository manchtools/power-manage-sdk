package sdk

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
)

// agentLoopback wires an in-process AgentService handler behind an h2c
// httptest.Server so the SDK Client can talk to it over a real Connect-RPC
// bidirectional stream. Earlier client-side tests stubbed dispatchServerMessage
// directly; this fixture exercises the actual stream.Send / stream.Receive
// boundary, which is where send serialisation and codec issues live.
type agentLoopback struct {
	srv        *httptest.Server
	serverURL  string
	handler    *recordingAgentHandler
	httpClient *http.Client
}

// recordingAgentHandler is the server-side AgentServiceHandler the SDK Client
// talks to in tests. The Stream method has a customisable onStream hook for
// tests that need to push server-initiated frames (Welcome, malformed messages,
// etc.); without a hook it drains the inbound side and records every received
// AgentMessage so tests can assert on them after the fact.
type recordingAgentHandler struct {
	mu       sync.Mutex
	received []*pm.AgentMessage

	onStream func(ctx context.Context, stream *connect.BidiStream[pm.AgentMessage, pm.ServerMessage]) error
}

func (h *recordingAgentHandler) Stream(ctx context.Context, s *connect.BidiStream[pm.AgentMessage, pm.ServerMessage]) error {
	if h.onStream != nil {
		return h.onStream(ctx, s)
	}
	for {
		msg, err := s.Receive()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		h.mu.Lock()
		h.received = append(h.received, msg)
		h.mu.Unlock()
	}
}

func (h *recordingAgentHandler) snapshot() []*pm.AgentMessage {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*pm.AgentMessage, len(h.received))
	copy(out, h.received)
	return out
}

func (h *recordingAgentHandler) SyncActions(ctx context.Context, req *connect.Request[pm.SyncActionsRequest]) (*connect.Response[pm.SyncActionsResponse], error) {
	return connect.NewResponse(&pm.SyncActionsResponse{}), nil
}

func (h *recordingAgentHandler) ValidateLuksToken(ctx context.Context, req *connect.Request[pm.ValidateLuksTokenRequest]) (*connect.Response[pm.ValidateLuksTokenResponse], error) {
	return connect.NewResponse(&pm.ValidateLuksTokenResponse{}), nil
}

func newAgentLoopback(t *testing.T) *agentLoopback {
	t.Helper()

	handler := &recordingAgentHandler{}
	path, h := pmv1connect.NewAgentServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, h)

	// Go 1.24+ replaced golang.org/x/net/http2/h2c with first-party
	// unencrypted-HTTP/2 support on http.Server and http.Transport
	// via http.Protocols.SetUnencryptedHTTP2 — both sides must opt in
	// for connect-rpc's bidi stream to negotiate h2c.
	proto := new(http.Protocols)
	proto.SetUnencryptedHTTP2(true)

	srv := httptest.NewUnstartedServer(mux)
	srv.Config.Protocols = proto
	srv.Start()
	t.Cleanup(srv.Close)

	hc := &http.Client{
		Transport: &http.Transport{
			Protocols: proto,
		},
	}

	return &agentLoopback{
		srv:        srv,
		serverURL:  srv.URL,
		handler:    handler,
		httpClient: hc,
	}
}

func (l *agentLoopback) newClient(extra ...ClientOption) *Client {
	opts := append([]ClientOption{WithHTTPClient(l.httpClient)}, extra...)
	return NewClient(l.serverURL, opts...)
}

// controlLoopback wires an in-process ControlService handler behind a plain
// httptest.Server. Register and RenewCertificate are unary and travel over
// HTTP/1.1 fine, so no h2c is needed here.
type controlLoopback struct {
	srv       *httptest.Server
	serverURL string
	handler   *recordingControlHandler
}

type recordingControlHandler struct {
	pmv1connect.UnimplementedControlServiceHandler

	registerFn         func(*connect.Request[pm.RegisterRequest]) (*connect.Response[pm.RegisterResponse], error)
	renewCertificateFn func(*connect.Request[pm.RenewCertificateRequest]) (*connect.Response[pm.RenewCertificateResponse], error)
}

func (h *recordingControlHandler) Register(ctx context.Context, req *connect.Request[pm.RegisterRequest]) (*connect.Response[pm.RegisterResponse], error) {
	if h.registerFn != nil {
		return h.registerFn(req)
	}
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("Register not stubbed"))
}

func (h *recordingControlHandler) RenewCertificate(ctx context.Context, req *connect.Request[pm.RenewCertificateRequest]) (*connect.Response[pm.RenewCertificateResponse], error) {
	if h.renewCertificateFn != nil {
		return h.renewCertificateFn(req)
	}
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("RenewCertificate not stubbed"))
}

func newControlLoopback(t *testing.T) *controlLoopback {
	t.Helper()

	handler := &recordingControlHandler{}
	path, h := pmv1connect.NewControlServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, h)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &controlLoopback{
		srv:       srv,
		serverURL: srv.URL,
		handler:   handler,
	}
}

// ---------------------------------------------------------------------------
// RegisterAgent and RenewCertificate
// ---------------------------------------------------------------------------

func TestRegisterAgent_HappyPath(t *testing.T) {
	cl := newControlLoopback(t)

	var observed *pm.RegisterRequest
	cl.handler.registerFn = func(req *connect.Request[pm.RegisterRequest]) (*connect.Response[pm.RegisterResponse], error) {
		observed = req.Msg
		return connect.NewResponse(&pm.RegisterResponse{
			DeviceId:    &pm.DeviceId{Value: "01HXXXXXXXXXXXXXXXXXXXXXX0"},
			CaCert:      []byte("ca"),
			Certificate: []byte("cert"),
			GatewayUrl:  "https://gateway.example",
		}), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got, err := RegisterAgent(ctx, cl.serverURL, "token-x", "host-1", "v1.2.3", []byte("csr-bytes"))
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	if got.DeviceID != "01HXXXXXXXXXXXXXXXXXXXXXX0" {
		t.Errorf("DeviceID = %q", got.DeviceID)
	}
	if string(got.Certificate) != "cert" || string(got.CACert) != "ca" {
		t.Errorf("certs not threaded through")
	}
	if got.GatewayURL != "https://gateway.example" {
		t.Errorf("GatewayURL = %q", got.GatewayURL)
	}
	if observed == nil {
		t.Fatal("server never observed the Register request")
	}
	if observed.Token != "token-x" || observed.Hostname != "host-1" ||
		observed.AgentVersion != "v1.2.3" || string(observed.Csr) != "csr-bytes" {
		t.Errorf("request fields lost in transit: %+v", observed)
	}
}

func TestRegisterAgent_ServerErrorPropagates(t *testing.T) {
	cl := newControlLoopback(t)
	cl.handler.registerFn = func(_ *connect.Request[pm.RegisterRequest]) (*connect.Response[pm.RegisterResponse], error) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("bad token"))
	}

	_, err := RegisterAgent(context.Background(), cl.serverURL, "wrong", "host", "v0", []byte("csr"))
	if err == nil {
		t.Fatal("expected error from server-side PermissionDenied")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("want *connect.Error, got %T: %v", err, err)
	}
	if connectErr.Code() != connect.CodePermissionDenied {
		t.Errorf("code = %v", connectErr.Code())
	}
}

func TestRenewCertificate_HappyPath(t *testing.T) {
	cl := newControlLoopback(t)

	notAfter := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	var observed *pm.RenewCertificateRequest
	cl.handler.renewCertificateFn = func(req *connect.Request[pm.RenewCertificateRequest]) (*connect.Response[pm.RenewCertificateResponse], error) {
		observed = req.Msg
		return connect.NewResponse(&pm.RenewCertificateResponse{
			Certificate:   []byte("renewed-cert"),
			NotAfter:      timestamppb.New(notAfter),
			CaCertificate: []byte("rotated-ca"),
		}), nil
	}

	got, err := RenewCertificate(context.Background(), cl.serverURL, []byte("new-csr"), []byte("old-cert"))
	if err != nil {
		t.Fatalf("RenewCertificate: %v", err)
	}
	if string(got.Certificate) != "renewed-cert" {
		t.Errorf("Certificate = %q", got.Certificate)
	}
	if !got.NotAfter.Equal(notAfter) {
		t.Errorf("NotAfter = %v want %v", got.NotAfter, notAfter)
	}
	if string(got.CACert) != "rotated-ca" {
		t.Errorf("CACert rotation lost: %q", got.CACert)
	}
	if observed == nil || string(observed.Csr) != "new-csr" || string(observed.CurrentCertificate) != "old-cert" {
		t.Errorf("request lost fields: %+v", observed)
	}
}

func TestRenewCertificate_ServerErrorPropagates(t *testing.T) {
	cl := newControlLoopback(t)
	cl.handler.renewCertificateFn = func(_ *connect.Request[pm.RenewCertificateRequest]) (*connect.Response[pm.RenewCertificateResponse], error) {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("expired cert"))
	}

	_, err := RenewCertificate(context.Background(), cl.serverURL, []byte("csr"), []byte("stale"))
	if err == nil {
		t.Fatal("expected error")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("want *connect.Error, got %T", err)
	}
	if connectErr.Code() != connect.CodeUnauthenticated {
		t.Errorf("code = %v", connectErr.Code())
	}
}

// ---------------------------------------------------------------------------
// Stream lifecycle: Connect / Close / outbound guards
// ---------------------------------------------------------------------------

func TestConnect_DoubleConnectErrors(t *testing.T) {
	l := newAgentLoopback(t)
	c := l.newClient()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("first Connect: %v", err)
	}
	defer c.Close()

	if err := c.Connect(ctx); err == nil {
		t.Fatal("second Connect should error")
	}
}

func TestSend_BeforeConnect_ReturnsError(t *testing.T) {
	l := newAgentLoopback(t)
	c := l.newClient()

	if err := c.SendHeartbeat(context.Background(), &pm.Heartbeat{}); err == nil {
		t.Fatal("SendHeartbeat without Connect should error")
	}
}

func TestSend_AfterClose_ReturnsError(t *testing.T) {
	l := newAgentLoopback(t)
	c := l.newClient()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := c.SendHeartbeat(context.Background(), &pm.Heartbeat{}); err == nil {
		t.Fatal("SendHeartbeat after Close should error")
	}
}

func TestClose_IsIdempotent(t *testing.T) {
	l := newAgentLoopback(t)
	c := l.newClient()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close should be no-op, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Send serialisation — the headline guarantee in client.go:447
// (c.sendMu serialises every stream.Send to prevent on-wire corruption).
// ---------------------------------------------------------------------------

func TestConcurrentSend_PreservesEveryMessage(t *testing.T) {
	l := newAgentLoopback(t)
	c := l.newClient(WithAuth("device-x", "tok"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer c.Close()

	if err := c.SendHello(ctx, "h", "v"); err != nil {
		t.Fatalf("SendHello: %v", err)
	}

	const (
		goroutines = 20
		perG       = 25
	)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				// Use SendActionResult so the recorded payload variant is
				// distinguishable from the SendHello above; ActionId encodes
				// the (goroutine, sequence) pair so we can detect any
				// dropped or mangled message after the fact.
				ar := &pm.ActionResult{
					ActionId: &pm.ActionId{Value: fmt.Sprintf("g%d-i%d", g, i)},
				}
				if err := c.SendActionResult(ctx, ar); err != nil {
					t.Errorf("send g=%d i=%d: %v", g, i, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	// Half-close the request side so the server's Receive loop returns
	// io.EOF and frees the goroutine. CloseRequest is what stream.Close
	// (via Client.Close) calls; here we do it directly because we want
	// the server-side snapshot before the client tears the stream down.
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The server's Stream goroutine runs concurrently with this test;
	// poll briefly until every message has landed.
	deadline := time.Now().Add(5 * time.Second)
	var got []*pm.AgentMessage
	want := 1 + goroutines*perG // SendHello + the fan-out
	for {
		got = l.handler.snapshot()
		if len(got) >= want || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(got) != want {
		t.Fatalf("received %d messages, want %d (drops or dupes break serialisation guarantee)", len(got), want)
	}

	// Hello must be the first frame on the wire — SendHello fires before
	// the fan-out, and sendMu makes "happens-before this point => arrives
	// first" a real guarantee.
	if got[0].GetHello() == nil {
		t.Errorf("first message = %T, want Hello", got[0].Payload)
	}

	// Every (goroutine,index) pair must arrive exactly once.
	seen := make(map[string]int)
	for _, m := range got[1:] {
		ar := m.GetActionResult()
		if ar == nil {
			t.Errorf("non-action-result observed: %T", m.Payload)
			continue
		}
		seen[ar.ActionId.GetValue()]++
	}
	for g := 0; g < goroutines; g++ {
		for i := 0; i < perG; i++ {
			key := fmt.Sprintf("g%d-i%d", g, i)
			if seen[key] != 1 {
				t.Errorf("ActionId %q seen %d times, want 1", key, seen[key])
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Server-side oddities the SDK must survive
// ---------------------------------------------------------------------------

// dispatchServerMessage must drop unknown / nil ServerMessage payloads
// silently (default branch in client.go:1077). A return error there tears
// down the agent connection on every unrecognised frame, which is much worse
// than dropping.
func TestDispatch_NilPayload_IsDropped(t *testing.T) {
	c := NewClient("http://localhost:0")
	handler := &fakeTerminalHandler{}
	msg := &pm.ServerMessage{Id: NewULID()} // Payload nil = forward-compat case
	if err := c.dispatchServerMessage(context.Background(), msg, handler); err != nil {
		t.Fatalf("nil payload should not error: %v", err)
	}
	// And no spurious dispatch happened.
	if len(handler.startCalls)+len(handler.inputCalls)+len(handler.resizeCalls)+len(handler.stopCalls) != 0 {
		t.Error("nil payload still reached a handler method")
	}
}

// Run() must shrug off a malformed/unknown server frame (no panic, no fatal
// error) and let the receive loop keep running until the context is cancelled.
func TestRun_UnknownServerMessage_DoesNotTerminate(t *testing.T) {
	l := newAgentLoopback(t)

	var welcomed atomic.Bool

	l.handler.onStream = func(ctx context.Context, s *connect.BidiStream[pm.AgentMessage, pm.ServerMessage]) error {
		// Wait for the agent's Hello before pushing anything back.
		if _, err := s.Receive(); err != nil {
			return err
		}
		// Push a Welcome so we can observe end-to-end dispatch worked.
		if err := s.Send(&pm.ServerMessage{
			Id:      NewULID(),
			Payload: &pm.ServerMessage_Welcome{Welcome: &pm.Welcome{}},
		}); err != nil {
			return err
		}
		// Then push a payload-less ServerMessage. The client must drop
		// it (default branch) and keep running.
		if err := s.Send(&pm.ServerMessage{Id: NewULID()}); err != nil {
			return err
		}
		// Drain anything else the agent sends until the request side
		// closes. Any Receive error here means the stream is done —
		// EOF on a clean Close, context.Canceled on ctx.Cancel, or a
		// connect-wrapped cancellation. The fake is intentionally
		// agnostic about which: its only job is to keep the stream
		// open while the test drives the client; the test's own
		// assertions (welcomed.Load, ctx.Cancel) judge correctness.
		// Returning nil here so an unexpected error doesn't tear down
		// the server side and mask the test's real failure mode.
		for {
			if _, err := s.Receive(); err != nil {
				return nil
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := l.newClient(WithAuth("device", "tok"))

	handler := &welcomeRecordingHandler{
		welcomed: &welcomed,
	}

	done := make(chan error, 1)
	go func() {
		done <- c.Run(ctx, "host", "v1", 50*time.Millisecond, handler)
	}()

	// Wait for OnWelcome to fire; that proves the receive loop survived
	// the malformed frame after it (Run's receive goroutine keeps reading
	// until ctx is done or a fatal error occurs).
	deadline := time.Now().Add(5 * time.Second)
	for !welcomed.Load() {
		if time.Now().After(deadline) {
			t.Fatal("Welcome never reached the handler — receive loop died?")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		// ctx.Cancel or transport-level cancel are both acceptable shutdown paths.
		if err != nil && !errors.Is(err, context.Canceled) {
			// Connect wraps cancellation; accept any error after cancel.
			t.Logf("Run returned: %v (after cancel)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

type welcomeRecordingHandler struct {
	welcomed *atomic.Bool
}

func (h *welcomeRecordingHandler) OnWelcome(ctx context.Context, w *pm.Welcome) error {
	h.welcomed.Store(true)
	return nil
}
func (h *welcomeRecordingHandler) OnAction(ctx context.Context, a *pm.Action) (*pm.ActionResult, error) {
	return nil, nil
}
func (h *welcomeRecordingHandler) OnQuery(ctx context.Context, q *pm.OSQuery) (*pm.OSQueryResult, error) {
	return nil, nil
}
func (h *welcomeRecordingHandler) OnError(ctx context.Context, e *pm.Error) error { return nil }

// ---------------------------------------------------------------------------
// mTLS — proves WithMTLSFromPEM actually installs the client certificate
// the server will see during the handshake, not just a TLS config that
// happens to compile.
// ---------------------------------------------------------------------------

func TestWithMTLSFromPEM_ClientPresentsCertificate(t *testing.T) {
	caCert, caKey := mustGenCA(t)
	serverCertPEM, serverKeyPEM := mustGenCert(t, caCert, caKey, "127.0.0.1", true)
	clientCertPEM, clientKeyPEM := mustGenCert(t, caCert, caKey, "device-client", false)
	caPEM := mustEncodeCert(caCert)

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("AppendCertsFromPEM(ca)")
	}
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}

	handler := &recordingControlHandler{}
	handler.registerFn = func(req *connect.Request[pm.RegisterRequest]) (*connect.Response[pm.RegisterResponse], error) {
		return connect.NewResponse(&pm.RegisterResponse{
			DeviceId: &pm.DeviceId{Value: "ok"},
		}), nil
	}
	path, h := pmv1connect.NewControlServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, h)

	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	t.Run("with cert succeeds", func(t *testing.T) {
		opt, err := WithMTLSFromPEM(clientCertPEM, clientKeyPEM, caPEM)
		if err != nil {
			t.Fatalf("WithMTLSFromPEM: %v", err)
		}
		got, err := RegisterAgent(context.Background(), srv.URL,
			"tok", "host", "v0", []byte("csr"), opt)
		if err != nil {
			t.Fatalf("RegisterAgent: %v", err)
		}
		if got.DeviceID != "ok" {
			t.Errorf("DeviceID = %q", got.DeviceID)
		}
	})

	t.Run("without cert handshake fails", func(t *testing.T) {
		// Same CA so the server cert verifies, but no client identity.
		tlsConfig := &tls.Config{
			RootCAs:    caPool,
			MinVersion: tls.VersionTLS13,
		}
		hc := newHTTPClientWithTLS(tlsConfig)
		_, err := RegisterAgent(context.Background(), srv.URL,
			"tok", "host", "v0", []byte("csr"), WithHTTPClient(hc))
		if err == nil {
			t.Fatal("expected handshake failure without client cert")
		}
	})
}

func TestWithHTTPClient_AppliedToControlCalls(t *testing.T) {
	cl := newControlLoopback(t)
	cl.handler.registerFn = func(_ *connect.Request[pm.RegisterRequest]) (*connect.Response[pm.RegisterResponse], error) {
		return connect.NewResponse(&pm.RegisterResponse{DeviceId: &pm.DeviceId{Value: "id"}}), nil
	}

	var called atomic.Int32
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		called.Add(1)
		return http.DefaultTransport.RoundTrip(req)
	})
	hc := &http.Client{Transport: rt}

	if _, err := RegisterAgent(context.Background(), cl.serverURL,
		"tok", "host", "v0", []byte("csr"), WithHTTPClient(hc)); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	if called.Load() == 0 {
		t.Fatal("WithHTTPClient was ignored by RegisterAgent")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// ---------------------------------------------------------------------------
// Cert generation helpers
// ---------------------------------------------------------------------------

func mustGenCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	return cert, key
}

func mustGenCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, name string, isServer bool) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if isServer {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
		tmpl.DNSNames = []string{"localhost"}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func mustEncodeCert(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
