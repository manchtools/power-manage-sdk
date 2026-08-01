// Package sdk provides a client library for communicating with the power-manage server.
package sdk

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/go-playground/validator/v10"
	"github.com/oklog/ulid/v2"
	"golang.org/x/net/http2"

	pm "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage-sdk/validate"
)

// Heartbeat interval bounds. The SDK clamps server-supplied values from
// Welcome.heartbeat_interval into this range before applying them, so a
// misconfigured or malicious server can never push the cadence outside
// what's safe for both sides (too fast = stream spam, too slow = agent
// looks dead to control's liveness tracking).
const (
	MinHeartbeatInterval = 5 * time.Second
	MaxHeartbeatInterval = 5 * time.Minute
)

// Client provides methods to communicate with the power-manage server.
type Client struct {
	client    powermanagev1connect.AgentServiceClient
	deviceID  string
	authToken string
	logger    *slog.Logger

	// httpClient is the underlying transport carrier, retained so the agent
	// can release its idle connections on reconnect (CloseIdleConnections) and
	// not leak a transport per reconnect attempt (WS13 #8).
	httpClient *http.Client

	// validator enforces the inbound `validate` gotags on each server command
	// before dispatch. Created in NewClient.
	validator *validator.Validate

	mu     sync.RWMutex
	stream *connect.BidiStreamForClient[pm.AgentMessage, pm.ServerMessage]

	// deliveryCh feeds the per-Run delivery worker. Manifest deliveries are
	// handed to a single worker goroutine (off the receive loop) so recording
	// and running one can no longer head-of-line-block TerminalStop/Input/
	// Resize (WS13 #7). A single worker preserves one-at-a-time, in-order
	// handling; the buffered channel bounds memory. Non-nil only while Run()
	// is active; guarded by mu.
	deliveryCh chan *pm.ManifestDelivery

	// sendSem is a buffered-1 channel used as a ctx-aware send lock. It
	// serializes all stream.Send() calls — concurrent writes on a bidi
	// stream are not safe and can corrupt messages on the wire — while
	// letting a sender abandon its claim on its own ctx deadline instead of
	// blocking indefinitely behind a stalled send (WS16 #1). Initialised by
	// NewClient.
	sendSem chan struct{}

	// pendingMu protects correlated request-response traffic on the stream.
	pendingMu       sync.Mutex
	pendingRequests map[string]chan *pm.ServerMessage

	// heartbeatUpdate is the channel Run's heartbeat goroutine reads
	// to reset its ticker when Welcome arrives with a new interval.
	// Non-nil only while Run() is active; guarded by mu.
	heartbeatUpdate chan time.Duration

	// invSem and luksRevokeSem bound how many server-originated
	// RequestInventory / RevokeLuksDeviceKey handlers run concurrently.
	// Each spawns a goroutine (inventory forks osquery; revoke does a
	// request-response on the stream), so an unbounded flood from a
	// compromised or buggy server could exhaust memory and goroutines.
	// Acquisition is non-blocking: excess is DROPPED, not queued (WS6
	// #11). Initialised by NewClient.
	invSem        chan struct{}
	luksRevokeSem chan struct{}
}

const (
	// inventoryDispatchConcurrency bounds concurrent server-originated
	// inventory collections. One full osquery scan at a time is the
	// realistic need; 2 gives a little slack without risking exhaustion.
	inventoryDispatchConcurrency = 2
	// luksRevokeDispatchConcurrency bounds concurrent LUKS device-key
	// revocations dispatched from the server.
	luksRevokeDispatchConcurrency = 2

	// maxInboundMessageBytes bounds the size of a single inbound
	// ServerMessage the agent will decode. The agent only ever receives
	// small control frames (actions, queries, terminal I/O chunks capped
	// at 64 KiB, LUKS request-response) — none legitimately approach this
	// size. Without a bound, a compromised or buggy server could push a
	// multi-gigabyte frame and force the agent to allocate it, an OOM /
	// DoS vector. 16 MiB is comfortably above any real frame yet refuses
	// a frame whose only purpose is to exhaust memory. Enforced via
	// connect.WithReadMaxBytes in NewClient; the connection that receives
	// an oversized frame is torn down with a resource-exhausted error.
	maxInboundMessageBytes = 16 << 20 // 16 MiB

	// deliveryQueueDepth bounds how many manifest deliveries can wait for the
	// single delivery worker (WS13 #7). Deep enough to absorb any legitimate
	// burst; a backlog beyond it means a pathological flood, so the excess is
	// dropped rather than queued unbounded or allowed to block the receive
	// loop. Dropping is safe by construction: a dropped delivery was never
	// receipted, so control redelivers it.
	deliveryQueueDepth = 256
)

// NewClient creates a new SDK client.
func NewClient(serverURL string, opts ...ClientOption) *Client {
	c := &Client{
		logger:        slog.Default(),
		validator:     validate.NewValidator(),
		sendSem:       make(chan struct{}, 1),
		invSem:        make(chan struct{}, inventoryDispatchConcurrency),
		luksRevokeSem: make(chan struct{}, luksRevokeDispatchConcurrency),
	}

	// http.DefaultClient (no Timeout) is correct here: the agent client
	// drives a long-lived bidi stream, and a whole-request timeout would
	// kill it. In production NewClient is always given a WithMTLS* option
	// that replaces this anyway. (The unary RegisterAgent/RenewCertificate
	// bootstrap calls use the bounded bootstrapHTTPClient instead.)
	httpClient := http.DefaultClient
	for _, opt := range opts {
		opt.apply(c, &httpClient)
	}
	c.httpClient = httpClient

	// Bound the size of inbound ServerMessages. A compromised or buggy
	// server could otherwise push an arbitrarily large frame and force
	// the agent to allocate it (OOM/DoS). connect.WithReadMaxBytes makes
	// the connection that receives an oversized frame fail with a
	// resource-exhausted error and tear down cleanly, rather than
	// allocate. The long-lived bidi stream is unaffected for normal
	// (small) control frames.
	c.client = powermanagev1connect.NewAgentServiceClient(httpClient, serverURL,
		connect.WithReadMaxBytes(maxInboundMessageBytes))
	return c
}

// CloseIdleConnections releases idle keep-alive connections held by this
// client's transport. The agent calls it when tearing down a connection session
// before reconnecting (WS13 #8): without it, each reconnect builds a fresh
// client whose mTLS transport keeps its own idle-connection pool, leaking
// sockets/file-descriptors across a long-lived reconnect loop. Safe to call on a
// client with no custom transport (http.DefaultClient.Transport) or a nil
// client.
func (c *Client) CloseIdleConnections() {
	if c == nil || c.httpClient == nil {
		return
	}
	c.httpClient.CloseIdleConnections()
}

// ClientOption configures the client.
type ClientOption interface {
	apply(*Client, **http.Client)
}

type funcOption struct {
	f func(*Client, **http.Client)
}

func (fo *funcOption) apply(c *Client, hc **http.Client) {
	fo.f(c, hc)
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(hc *http.Client) ClientOption {
	return &funcOption{func(c *Client, httpClient **http.Client) {
		*httpClient = hc
	}}
}

// WithAuth sets the device ID and auth token.
func WithAuth(deviceID, authToken string) ClientOption {
	return &funcOption{func(c *Client, _ **http.Client) {
		c.deviceID = deviceID
		c.authToken = authToken
	}}
}

// WithLogger sets a custom structured logger for the client.
func WithLogger(l *slog.Logger) ClientOption {
	return &funcOption{func(c *Client, _ **http.Client) {
		c.logger = l
	}}
}

// WithMTLS configures the client to use mTLS authentication.
// certFile and keyFile are the paths to the client certificate and key.
// caFile is the path to the CA certificate for server verification.
func WithMTLS(certFile, keyFile, caFile string) (ClientOption, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, errors.New("failed to parse CA certificate")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}

	return &funcOption{func(c *Client, httpClient **http.Client) {
		*httpClient = newHTTPClientWithTLS(tlsConfig)
	}}, nil
}

// WithTLSConfig configures the client with a custom TLS configuration.
func WithTLSConfig(tlsConfig *tls.Config) ClientOption {
	return &funcOption{func(c *Client, httpClient **http.Client) {
		*httpClient = newHTTPClientWithTLS(tlsConfig)
	}}
}

// WithMTLSFromPEM configures mTLS using PEM-encoded certificate data.
//
// Trust is strict: the returned TLS config verifies the server ONLY
// against caPEM. This is the correct setup for talking to the
// internal-CA-signed control agent listener over mTLS — system roots
// are NOT consulted, so a cert signed by any public CA cannot
// impersonate control even if its SNI matches.
//
// For reaching servers whose public-facing HTTPS cert is signed by
// a public CA (typically a Traefik reverse proxy with Let's Encrypt
// in front of the control server), pair the client certificate with
// system roots via WithMTLSFromPEMAndSystemRoots instead.
func WithMTLSFromPEM(certPEM, keyPEM, caPEM []byte) (ClientOption, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse client certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("failed to parse CA certificate")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}

	return &funcOption{func(c *Client, httpClient **http.Client) {
		*httpClient = newHTTPClientWithTLS(tlsConfig)
	}}, nil
}

// WithMTLSFromPEMAndSystemRoots is like WithMTLSFromPEM but the
// server-verification root pool contains caPEM PLUS the host's
// system roots. Use this when the server sits behind a public CA
// (e.g. a Traefik reverse proxy terminating TLS with Let's Encrypt)
// and the client cert must still authenticate the agent's identity
// at the application layer — for example the
// ControlService.RenewCertificate RPC, which can travel over a
// public-LE-fronted HTTPS endpoint and also passes the current
// certificate in the request body.
//
// Do NOT use this for the agent's mTLS stream: control's agent
// listener is internal-CA only, and broadening its trust to system
// roots lets any publicly-trusted cert with a matching SNI
// impersonate it.
func WithMTLSFromPEMAndSystemRoots(certPEM, keyPEM, caPEM []byte) (ClientOption, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse client certificate: %w", err)
	}

	caPool, err := x509.SystemCertPool()
	if err != nil || caPool == nil {
		caPool = x509.NewCertPool()
	}
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("failed to parse CA certificate")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}

	return &funcOption{func(c *Client, httpClient **http.Client) {
		*httpClient = newHTTPClientWithTLS(tlsConfig)
	}}, nil
}

// newHTTPClientWithTLS creates an HTTP client with HTTP/2 support enabled.
// A bare http.Transport with a custom TLSClientConfig disables Go's automatic
// HTTP/2 negotiation, so we explicitly configure it via http2.ConfigureTransport.
// If the HTTP/2 configuration fails the transport silently falls back to HTTP/1.1,
// which breaks Connect bidirectional streaming — log it loudly so the operator can
// see why the agent is unable to reach control.
func newHTTPClientWithTLS(tlsConfig *tls.Config) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	if err := http2.ConfigureTransport(transport); err != nil {
		slog.Default().Warn("failed to configure HTTP/2 transport; falling back to HTTP/1.1 (bidirectional streaming will not work)", "error", err)
	}
	return &http.Client{Transport: transport}
}

// WithH2C configures the client to use HTTP/2 cleartext (h2c) without TLS.
// This is useful for development/testing when connecting to servers that
// use h2c instead of HTTPS.
// WARNING: Only use this for development/testing - data is not encrypted!
func WithH2C() ClientOption {
	return &funcOption{func(c *Client, httpClient **http.Client) {
		*httpClient = &http.Client{
			Transport: &http2.Transport{
				// Allow h2c (HTTP/2 without TLS)
				AllowHTTP: true,
				// Use a custom DialTLSContext that returns a plain TCP connection
				DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
					d := net.Dialer{
						Timeout:   30 * time.Second,
						KeepAlive: 30 * time.Second,
					}
					return d.DialContext(ctx, network, addr)
				},
				// Disable connection pooling to avoid stale connections
				DisableCompression: true,
			},
		}
	}}
}

// bootstrapHTTPClient is the default client for the unauthenticated
// RegisterAgent / RenewCertificate bootstrap calls. Unlike
// http.DefaultClient it has a bounded Timeout (a hung or malicious
// control endpoint must not be able to wedge enrollment/renewal forever)
// and a TLS 1.3 floor. Proxy support is deliberately retained
// (http.ProxyFromEnvironment): the agent runs as root under systemd with
// a controlled environment, the channel is TLS-authenticated, and the
// optional enrollment CA-pin catches a wrong-CA outcome — so honoring an
// enterprise proxy is the right trade-off over breaking proxied
// deployments. Overridable via ClientOption (the renewal mTLS variants
// replace the client entirely).
func bootstrapHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13},
	}
	// Preserve HTTP/2 parity with http.DefaultClient for the https
	// control endpoint; falls back to HTTP/1.1 if configuration fails
	// (unary register/renew works over either).
	if err := http2.ConfigureTransport(transport); err != nil {
		slog.Default().Warn("bootstrap: failed to configure HTTP/2 transport; falling back to HTTP/1.1", "error", err)
	}
	return &http.Client{
		Timeout:   60 * time.Second,
		Transport: transport,
	}
}

// RegisterAgentResult contains the result of agent registration.
type RegisterAgentResult struct {
	DeviceID    string
	CACert      []byte
	Certificate []byte
	// ControlURL is where the agent dials its AgentService stream — control's
	// agent listener, normally a different host from the API URL registration
	// went to.
	ControlURL string
	// ControlSealingPublicKey is control's deployment X25519 public key, raw
	// 32-byte encoding. The agent pins it alongside CACert and seals every
	// secret it reports to it.
	ControlSealingPublicKey []byte
}

// RegisterAgent registers an agent with the control server.
// This is a standalone function that uses ControlServiceClient (not AgentServiceClient).
// The controlURL is the control server's public API URL (where the web UI
// connects). The result's ControlURL is a DIFFERENT host — control's agent
// listener, which the agent dials for its stream.
//
// sealingPubKey is the raw 32-byte X25519 public key the agent generated for
// this enrollment; control seals to it for the lifetime of the device
// identity issued here. It is a required parameter rather than an option
// because an enrollment without it produces a device control can never send a
// secret to.
func RegisterAgent(ctx context.Context, controlURL string, token, hostname, agentVersion string, csr, sealingPubKey []byte, opts ...ClientOption) (*RegisterAgentResult, error) {
	c := &Client{}
	httpClient := bootstrapHTTPClient()
	for _, opt := range opts {
		opt.apply(c, &httpClient)
	}

	controlClient := powermanagev1connect.NewControlServiceClient(httpClient, controlURL)

	req := connect.NewRequest(&pm.RegisterRequest{
		Token:                 token,
		Hostname:              hostname,
		AgentVersion:          agentVersion,
		Csr:                   csr,
		AgentSealingPublicKey: sealingPubKey,
	})

	resp, err := controlClient.Register(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}

	return &RegisterAgentResult{
		DeviceID:                resp.Msg.DeviceId.GetValue(),
		CACert:                  resp.Msg.CaCert,
		Certificate:             resp.Msg.Certificate,
		ControlURL:              resp.Msg.ControlUrl,
		ControlSealingPublicKey: resp.Msg.ControlSealingPublicKey,
	}, nil
}

// RenewCertificateResult contains the result of certificate renewal.
type RenewCertificateResult struct {
	Certificate []byte
	NotAfter    time.Time
	CACert      []byte // Active CA certificate (non-empty when CA has been rotated)
}

// RenewCertificate renews a device certificate via the control server.
// The agent presents its current certificate for identity verification.
func RenewCertificate(ctx context.Context, controlURL string, csr, currentCert []byte, opts ...ClientOption) (*RenewCertificateResult, error) {
	c := &Client{}
	httpClient := bootstrapHTTPClient()
	for _, opt := range opts {
		opt.apply(c, &httpClient)
	}

	controlClient := powermanagev1connect.NewControlServiceClient(httpClient, controlURL)

	req := connect.NewRequest(&pm.RenewCertificateRequest{
		Csr:                csr,
		CurrentCertificate: currentCert,
	})

	resp, err := controlClient.RenewCertificate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("renew certificate: %w", err)
	}

	return &RenewCertificateResult{
		Certificate: resp.Msg.Certificate,
		NotAfter:    resp.Msg.NotAfter.AsTime(),
		CACert:      resp.Msg.CaCertificate,
	}, nil
}

// StreamHandler handles messages received from the server.
type StreamHandler interface {
	// OnWelcome is called when the server sends a welcome message.
	OnWelcome(ctx context.Context, welcome *pm.Welcome) error
	// OnManifestDelivery is called when control delivers a manifest on the
	// authenticated stream.
	//
	// The handler MUST durably record the delivery, keyed by its delivery_id,
	// before returning nil. The SDK sends DeliveryReceipt only on a nil
	// return, so a receipt can never claim durability the device does not
	// have; control keeps redelivering until it sees one. A delivery_id the
	// handler already holds is a retry: record-once, execute-once, return nil
	// again so the receipt is re-sent.
	//
	// Returning an error means the delivery was NOT recorded. No receipt is
	// sent and the error is logged; control redelivers.
	//
	// Execution is the handler's own business, driven off its durable record
	// and reported asynchronously with SendActionResult (per occurrence) and
	// SendManifestResult (once for the manifest).
	OnManifestDelivery(ctx context.Context, delivery *pm.ManifestDelivery) error
	// OnQuery is called when the server sends an OS query.
	OnQuery(ctx context.Context, query *pm.OSQuery) (*pm.OSQueryResult, error)
	// OnError is called when the server sends an error.
	OnError(ctx context.Context, err *pm.Error) error
}

// StreamingHandler extends StreamHandler with output streaming during manifest
// execution. Handlers that implement this interface receive a callback for
// pushing output chunks as the manifest's occurrences run.
type StreamingHandler interface {
	StreamHandler
	// OnManifestDeliveryWithStreaming carries the same durable-receipt
	// contract as OnManifestDelivery — nil return means recorded, and only
	// then does the SDK send the receipt. sendChunk streams per-occurrence
	// output while the manifest executes.
	OnManifestDeliveryWithStreaming(ctx context.Context, delivery *pm.ManifestDelivery, sendChunk func(*pm.OutputChunk) error) error
}

// LuksHandler extends StreamHandler with LUKS device-key revocation support.
// Handlers that implement this interface will receive revoke requests from the server.
type LuksHandler interface {
	StreamHandler
	// OnRevokeLuksDeviceKey is called when control requests revocation of a
	// LUKS device-bound key. The full message is delivered rather than the
	// bare action_id so the handler keeps whatever context later fields add.
	// Returns (success, errorMessage).
	OnRevokeLuksDeviceKey(ctx context.Context, req *pm.RevokeLuksDeviceKey) (bool, string)
}

// LogQueryHandler extends StreamHandler with remote log query support.
// Handlers that implement this interface can execute journalctl queries on the device.
type LogQueryHandler interface {
	StreamHandler
	// OnLogQuery is called when the server sends a log query request.
	OnLogQuery(ctx context.Context, query *pm.LogQuery) (*pm.LogQueryResult, error)
}

// InventoryHandler extends StreamHandler with device inventory collection support.
// Handlers that implement this interface can collect and send hardware/software inventory.
type InventoryHandler interface {
	StreamHandler
	// CollectInventory gathers hardware/software inventory from the device on
	// the agent's OWN schedule (on connect + every 24h). Returns nil if
	// collection is unavailable (e.g. osquery not installed).
	CollectInventory(ctx context.Context) *pm.DeviceInventory
	// OnRequestInventory handles a control-originated RequestInventory,
	// collecting the same inventory on demand and correlating it with the
	// request's query_id. Returns nil when collection is unavailable.
	OnRequestInventory(ctx context.Context, req *pm.RequestInventory) *pm.DeviceInventory
}

// TerminalHandler extends StreamHandler with remote terminal (PTY) session
// support. Handlers that implement this interface receive the four
// server-initiated session control messages from manchtools/power-manage-sdk#16
// and are responsible for allocating PTYs, relaying I/O, and reporting
// state back via Client.SendTerminalOutput / Client.SendTerminalStateChange.
//
// All four methods MUST return promptly: the SDK invokes them on the
// receive loop, so a slow handler will stall delivery of every other
// ServerMessage variant. Implementations should hand off to a per-session
// goroutine for any blocking I/O.
//
// A nil error from these methods means the request was accepted; the
// handler is expected to surface terminal-level failures via
// SendTerminalStateChange with a TERMINAL_SESSION_STATE_ERROR payload.
// Returning a non-nil error from OnTerminalStart/Input/Resize/Stop is
// treated as a fatal stream error and tears down the agent connection.
type TerminalHandler interface {
	StreamHandler
	// OnTerminalStart is called when the server requests a new PTY.
	// The handler should validate tty_user, allocate the PTY, kick off
	// I/O goroutines, and send a TERMINAL_SESSION_STATE_STARTED state
	// change. If allocation fails, it MUST send a STATE_ERROR instead.
	OnTerminalStart(ctx context.Context, req *pm.TerminalStart) error
	// OnTerminalInput is called for every stdin frame from the server.
	// The handler should write the bytes to the PTY of the matching
	// session_id and ignore (with a debug log) frames for unknown
	// sessions.
	OnTerminalInput(ctx context.Context, req *pm.TerminalInput) error
	// OnTerminalResize forwards a TIOCSWINSZ to the session's PTY.
	// Unknown sessions are ignored.
	OnTerminalResize(ctx context.Context, req *pm.TerminalResize) error
	// OnTerminalStop terminates the session and reverts any side effects
	// (shell unmask, temp home cleanup, etc.). Unknown sessions are
	// idempotent no-ops so the server can fire and forget on disconnect.
	OnTerminalStop(ctx context.Context, req *pm.TerminalStop) error
}

// Connect establishes a bidirectional stream with the server.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	if c.stream != nil {
		c.mu.Unlock()
		return errors.New("already connected")
	}

	stream := c.client.Stream(ctx)
	c.stream = stream
	c.mu.Unlock()

	return nil
}

// send serializes all writes to the bidirectional stream and honors ctx.
// Multiple goroutines (heartbeat, inventory, result sender) may call Send
// methods concurrently; without serialization this can corrupt messages.
//
// Both the send-lock acquisition AND the underlying stream.Send observe ctx,
// so a stalled peer (a full HTTP/2 flow-control window with no draining) can
// no longer wedge a sender — or every other sender queued behind it — past
// its own deadline (WS16 #1). At most one stream.Send is ever in flight: the
// send slot is held until the in-flight Send actually returns, even if the
// caller has already given up on ctx, so the on-wire serialization guarantee
// is preserved. A send that is abandoned on ctx stays pending until the
// stream is torn down (Close / run-ctx cancel on reconnect), which resets it.
func (c *Client) send(ctx context.Context, msg *pm.AgentMessage) error {
	c.mu.RLock()
	stream := c.stream
	c.mu.RUnlock()

	if stream == nil {
		return errors.New("not connected")
	}

	// Refuse up front if the caller's ctx is already done — don't queue
	// behind the send lock just to fail.
	if err := ctx.Err(); err != nil {
		return err
	}

	// Acquire the send slot ctx-aware: a waiting sender abandons its claim on
	// its own deadline instead of starving behind a stalled send.
	select {
	case c.sendSem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}

	// Run the blocking Send while holding the slot. The slot is released only
	// when stream.Send actually returns (in the goroutine), so a second Send
	// can never start concurrently with an abandoned one — no on-wire
	// corruption. errCh is buffered so the goroutine never blocks publishing
	// its result even after we have returned on ctx.
	errCh := make(chan error, 1)
	go func() {
		err := stream.Send(msg)
		<-c.sendSem
		errCh <- err
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SendHello sends a hello message to the server.
func (c *Client) SendHello(ctx context.Context, hostname, agentVersion string) error {
	c.mu.RLock()
	deviceID := c.deviceID
	authToken := c.authToken
	c.mu.RUnlock()

	return c.send(ctx, &pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_Hello{
			Hello: &pm.Hello{
				DeviceId:     &pm.DeviceId{Value: deviceID},
				AgentVersion: agentVersion,
				Hostname:     hostname,
				AuthToken:    authToken,
				Arch:         runtime.GOARCH,
			},
		},
	})
}

// SendHeartbeat sends a heartbeat message to the server.
func (c *Client) SendHeartbeat(ctx context.Context, hb *pm.Heartbeat) error {
	return c.send(ctx, &pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_Heartbeat{
			Heartbeat: hb,
		},
	})
}

// SendActionResult reports the outcome of one occurrence. The result must
// carry the delivery_id and occurrence_id it descends from; control keys
// ingestion on that pair, so a result replayed after a reconnect updates the
// same row instead of creating a second one.
func (c *Client) SendActionResult(ctx context.Context, result *pm.ActionResult) error {
	return c.send(ctx, &pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_ActionResult{
			ActionResult: result,
		},
	})
}

// SendManifestResult reports the outcome of a complete manifest, once, after
// its occurrences have reported individually.
func (c *Client) SendManifestResult(ctx context.Context, result *pm.ManifestResult) error {
	return c.send(ctx, &pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_ManifestResult{
			ManifestResult: result,
		},
	})
}

// SendDeliveryReceipt confirms that a delivery is durably recorded on this
// device. Control advances the delivery only on this frame, never on its own
// successful socket write, so the caller MUST NOT send it before the local
// commit has landed.
//
// runManifestDelivery calls this only after the handler returns nil, making the
// durable-record-before-receipt ordering structural.
func (c *Client) SendDeliveryReceipt(ctx context.Context, deliveryID string) error {
	return c.send(ctx, &pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_DeliveryReceipt{
			DeliveryReceipt: &pm.DeliveryReceipt{DeliveryId: deliveryID},
		},
	})
}

// SendOutputChunk sends an output chunk during action execution.
func (c *Client) SendOutputChunk(ctx context.Context, chunk *pm.OutputChunk) error {
	return c.send(ctx, &pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_OutputChunk{
			OutputChunk: chunk,
		},
	})
}

// SendQueryResult sends an OS query result to the server.
func (c *Client) SendQueryResult(ctx context.Context, result *pm.OSQueryResult) error {
	return c.send(ctx, &pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_QueryResult{
			QueryResult: result,
		},
	})
}

// SendLogQueryResult sends a log query result to the server.
func (c *Client) SendLogQueryResult(ctx context.Context, result *pm.LogQueryResult) error {
	return c.send(ctx, &pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_LogQueryResult{
			LogQueryResult: result,
		},
	})
}

// SendSecurityAlert sends a security alert to the server for audit logging.
func (c *Client) SendSecurityAlert(ctx context.Context, alert *pm.SecurityAlert) error {
	return c.send(ctx, &pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_SecurityAlert{
			SecurityAlert: alert,
		},
	})
}

// SendInventory sends device inventory to the server.
func (c *Client) SendInventory(ctx context.Context, inventory *pm.DeviceInventory) error {
	if inventory == nil {
		return nil
	}

	return c.send(ctx, &pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_Inventory{
			Inventory: inventory,
		},
	})
}

// SendTerminalOutput sends a stdout/stderr chunk from a remote terminal
// session back to the server. The TerminalHandler is responsible for
// chunking PTY reads to fit the proto's 64KB max data size.
func (c *Client) SendTerminalOutput(ctx context.Context, out *pm.TerminalOutput) error {
	return c.send(ctx, &pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_TerminalOutput{
			TerminalOutput: out,
		},
	})
}

// SendTerminalStateChange reports a terminal session lifecycle event
// (started, exited with code, error). Send STARTED immediately after
// the PTY is allocated, EXITED when the shell process exits cleanly,
// and ERROR for any failure that ends the session before STARTED or
// in flight.
func (c *Client) SendTerminalStateChange(ctx context.Context, change *pm.TerminalStateChange) error {
	return c.send(ctx, &pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_TerminalStateChange{
			TerminalStateChange: change,
		},
	})
}

// GetLuksKey sends a GetLuksKeyRequest on the stream and waits for the
// correlated response, matched by message ID.
//
// The returned passphrase is sealed to this device's enrollment recipient key.
// Opening it is the caller's job, at the narrow sink immediately before use —
// the SDK deliberately does not unseal here, so the plaintext never exists in
// a general-purpose transport helper.
func (c *Client) GetLuksKey(ctx context.Context, actionID string) (*pm.SealedValue, error) {
	id := NewULID()
	ch := c.registerPending(id)
	defer c.unregisterPending(id)

	if err := c.send(ctx, &pm.AgentMessage{
		Id: id,
		Payload: &pm.AgentMessage_GetLuksKey{
			GetLuksKey: &pm.GetLuksKeyRequest{
				ActionId: actionID,
			},
		},
	}); err != nil {
		return nil, fmt.Errorf("send get luks key request: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case resp, ok := <-ch:
		if !ok || resp == nil {
			return nil, errors.New("stream closed while waiting for GetLuksKey response")
		}
		if errMsg := resp.GetError(); errMsg != nil {
			return nil, fmt.Errorf("server error: %s", errMsg.Message)
		}
		luksResp := resp.GetGetLuksKey()
		if luksResp == nil {
			return nil, errors.New("unexpected response type")
		}
		// The response carries validate tags and nothing was checking them: a
		// blob too short to be a seal, or an absent one, would otherwise reach
		// the unseal call and fail there with a less honest error.
		if err := c.validateInbound(luksResp); err != nil {
			return nil, fmt.Errorf("invalid GetLuksKey response: %w", err)
		}
		return luksResp.Passphrase, nil
	}
}

// StoreLuksKey sends a StoreLuksKeyRequest on the stream and waits for the
// server confirmation.
//
// passphrase must already be sealed to control's deployment sealing key, with
// AAD binding this device and actionID. The SDK does not seal for the caller:
// sealing needs the recipient key and the action context, both of which belong
// to the agent, and a transport helper that accepted plaintext would be the
// one place a credential could be logged by accident.
func (c *Client) StoreLuksKey(ctx context.Context, actionID, devicePath string, passphrase *pm.SealedValue, reason pm.RotationReason) error {
	id := NewULID()
	ch := c.registerPending(id)
	defer c.unregisterPending(id)

	if err := c.send(ctx, &pm.AgentMessage{
		Id: id,
		Payload: &pm.AgentMessage_StoreLuksKey{
			StoreLuksKey: &pm.StoreLuksKeyRequest{
				ActionId:       actionID,
				DevicePath:     devicePath,
				Passphrase:     passphrase,
				RotationReason: reason,
			},
		},
	}); err != nil {
		return fmt.Errorf("send store luks key request: %w", err)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case resp, ok := <-ch:
		if !ok || resp == nil {
			return errors.New("stream closed while waiting for StoreLuksKey response")
		}
		if errMsg := resp.GetError(); errMsg != nil {
			return fmt.Errorf("server error: %s", errMsg.Message)
		}
		storeResp := resp.GetStoreLuksKey()
		if storeResp == nil {
			return errors.New("unexpected response type")
		}
		if !storeResp.Success {
			return errors.New("server rejected key storage")
		}
		return nil
	}
}

// StoreLpsPasswords reports one LPS execution's password rotations and waits for
// the server confirmation.
//
// Each rotation's password must already be sealed to control's deployment
// sealing key, with AAD binding the device, the action and that rotation's
// username — the username binding is what stops a blob being stored under a
// different account than the one it was generated for.
//
// Request/response are correlated by message id like every other stream call, so
// a failed batch is reported rather than silently dropped: LPS rotations are
// unrecoverable if lost — the agent has already changed the local password.
func (c *Client) StoreLpsPasswords(ctx context.Context, actionID string, rotations []*pm.LpsPasswordRotation) error {
	if len(rotations) == 0 {
		return errors.New("refusing to send an empty LPS rotation batch")
	}

	id := NewULID()
	ch := c.registerPending(id)
	defer c.unregisterPending(id)

	if err := c.send(ctx, &pm.AgentMessage{
		Id: id,
		Payload: &pm.AgentMessage_StoreLpsPasswords{
			StoreLpsPasswords: &pm.StoreLpsPasswordsRequest{
				ActionId:  actionID,
				Rotations: rotations,
			},
		},
	}); err != nil {
		return fmt.Errorf("send store lps passwords request: %w", err)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case resp, ok := <-ch:
		if !ok || resp == nil {
			return errors.New("stream closed while waiting for StoreLpsPasswords response")
		}
		if errMsg := resp.GetError(); errMsg != nil {
			return fmt.Errorf("server error: %s", errMsg.Message)
		}
		storeResp := resp.GetStoreLpsPasswords()
		if storeResp == nil {
			return errors.New("unexpected response type")
		}
		if !storeResp.Success {
			return errors.New("server rejected LPS password storage")
		}
		return nil
	}
}

// SendRevokeLuksDeviceKeyResult sends the result of a LUKS device key revocation back to the server.
func (c *Client) SendRevokeLuksDeviceKeyResult(ctx context.Context, actionID string, success bool, errMsg string) error {
	return c.send(ctx, &pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_RevokeLuksDeviceKeyResult{
			RevokeLuksDeviceKeyResult: &pm.RevokeLuksDeviceKeyResult{
				ActionId: actionID,
				Success:  success,
				Error:    errMsg,
			},
		},
	})
}

// registerPending creates a channel for receiving a correlated response.
func (c *Client) registerPending(id string) chan *pm.ServerMessage {
	ch := make(chan *pm.ServerMessage, 1)
	c.pendingMu.Lock()
	if c.pendingRequests == nil {
		c.pendingRequests = make(map[string]chan *pm.ServerMessage)
	}
	c.pendingRequests[id] = ch
	c.pendingMu.Unlock()
	return ch
}

// unregisterPending removes a pending request channel.
func (c *Client) unregisterPending(id string) {
	c.pendingMu.Lock()
	delete(c.pendingRequests, id)
	c.pendingMu.Unlock()
}

// deliverPending delivers a server message to a waiting request by ID.
// Returns true if the message was delivered (ID matched a pending request).
//
// The send is non-blocking: pending channels are buffered with capacity
// 1 (registerPending) and the request flow only reads once. If a second
// response arrives for the same ID — for example, the server retried a
// dispatch and the first reply was already consumed — there is no
// receiver and the second message would block the dispatcher loop
// forever. We log the drop so duplicates are visible in agent logs but
// keep the receive loop moving rather than stalling on a defunct
// request channel.
func (c *Client) deliverPending(msg *pm.ServerMessage) bool {
	c.pendingMu.Lock()
	ch, ok := c.pendingRequests[msg.Id]
	c.pendingMu.Unlock()
	if ok {
		select {
		case ch <- msg:
		default:
			c.logger.Warn("deliverPending: dropping duplicate response", "id", msg.Id)
		}
	}
	return ok
}

// Receive receives the next message from the server.
func (c *Client) Receive(ctx context.Context) (*pm.ServerMessage, error) {
	c.mu.RLock()
	stream := c.stream
	c.mu.RUnlock()

	if stream == nil {
		return nil, errors.New("not connected")
	}

	msg, err := stream.Receive()
	if err != nil {
		return nil, err
	}

	return msg, nil
}

// Close closes the stream connection and cancels every pending request.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stream == nil {
		return nil
	}

	// Cancel pending correlated requests.
	c.pendingMu.Lock()
	for id, ch := range c.pendingRequests {
		close(ch)
		delete(c.pendingRequests, id)
	}
	c.pendingMu.Unlock()

	// Close both request and response sides of the stream
	_ = c.stream.CloseRequest()
	_ = c.stream.CloseResponse()
	c.stream = nil
	return nil
}

// StartReceiver starts a background goroutine that receives stream messages and
// delivers them to pending correlated request channels.
// Returns a cancel function to stop the receiver. This is useful for CLI tools that
// need request-response correlation without the full Run() loop.
// The caller must call Connect() and SendHello() before calling this.
func (c *Client) StartReceiver(ctx context.Context) context.CancelFunc {
	rctx, cancel := context.WithCancel(ctx)
	go func() {
		for {
			msg, err := c.Receive(rctx)
			if err != nil {
				return
			}
			c.deliverPending(msg)
		}
	}()
	return cancel
}

// Run connects to the server and processes messages using the provided handler.
//
// heartbeatInterval is the initial cadence used until the server's
// Welcome message arrives. If Welcome.heartbeat_interval is set and
// falls within [MinHeartbeatInterval, MaxHeartbeatInterval], the SDK
// resets the heartbeat ticker to that value — both on the initial
// connect and on every subsequent reconnect (each reconnect is a fresh
// Run() call that receives a fresh Welcome). Out-of-range values are
// clamped; zero / unset keeps the caller-supplied interval.
func (c *Client) Run(ctx context.Context, hostname, agentVersion string, heartbeatInterval time.Duration, handler StreamHandler) error {
	if err := c.Connect(ctx); err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	if err := c.SendHello(ctx, hostname, agentVersion); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}

	// Start heartbeat goroutine
	heartbeatCtx, cancelHeartbeat := context.WithCancel(ctx)
	defer cancelHeartbeat()

	// Buffered channel (capacity 1, latest-wins) lets dispatchServerMessage
	// push a new interval without blocking. Published on Client so the
	// Welcome handler can find it; cleared on Run exit so a reconnect's
	// next Run() call starts from scratch.
	hbUpdate := make(chan time.Duration, 1)
	c.mu.Lock()
	c.heartbeatUpdate = hbUpdate
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.heartbeatUpdate = nil
		c.mu.Unlock()
	}()

	go func() {
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()

		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case d := <-hbUpdate:
				ticker.Reset(d)
			case <-ticker.C:
				hb := &pm.Heartbeat{}
				// Handler can populate heartbeat data if needed
				if err := c.SendHeartbeat(heartbeatCtx, hb); err != nil {
					return
				}
			}
		}
	}()

	// Inventory: send on connect + every 24 hours. safeGo guards the
	// loop so a panic in the agent-initiated CollectInventory path cannot
	// crash the whole agent process (a panic in a bare goroutine is
	// unrecoverable by the parent).
	if invHandler, ok := handler.(InventoryHandler); ok {
		c.safeGo("inventory-ticker", func() {
			// sendWithRetry sends inventory with up to 3 attempts at
			// 1s/3s/9s backoff. The 24-hour ticker means a single
			// transient send failure (network blip on connect) would
			// otherwise stall inventory for a full day. F035.
			sendWithRetry := func(inv *pm.DeviceInventory) {
				const maxAttempts = 3
				delay := time.Second
				for attempt := 1; attempt <= maxAttempts; attempt++ {
					err := c.SendInventory(heartbeatCtx, inv)
					if err == nil {
						return
					}
					if attempt == maxAttempts || heartbeatCtx.Err() != nil {
						c.logger.Warn("failed to send inventory", "error", err, "attempts", attempt)
						return
					}
					select {
					case <-heartbeatCtx.Done():
						return
					case <-time.After(delay):
					}
					delay *= 3
				}
			}

			// Initial inventory on connect
			if inv := invHandler.CollectInventory(heartbeatCtx); inv != nil {
				sendWithRetry(inv)
			}

			ticker := time.NewTicker(24 * time.Hour)
			defer ticker.Stop()

			for {
				select {
				case <-heartbeatCtx.Done():
					return
				case <-ticker.C:
					if inv := invHandler.CollectInventory(heartbeatCtx); inv != nil {
						sendWithRetry(inv)
					}
				}
			}
		})
	}

	// Delivery worker (WS13 #7): manifest deliveries are recorded and run on
	// this single goroutine, off the receive loop, so a long-running manifest
	// cannot head-of-line-block terminal control frames. One worker =
	// one-at-a-time, in-order handling; the buffered channel bounds memory.
	// Published on the Client so dispatchServerMessage can enqueue; cleared +
	// drained on Run exit.
	deliveryCh := make(chan *pm.ManifestDelivery, deliveryQueueDepth)
	workerCtx, cancelWorker := context.WithCancel(ctx)
	c.mu.Lock()
	c.deliveryCh = deliveryCh
	c.mu.Unlock()
	var deliveryWG sync.WaitGroup
	deliveryWG.Add(1)
	go func() {
		defer deliveryWG.Done()
		for delivery := range deliveryCh {
			// Skip queued deliveries once the connection is going down rather
			// than half-applying system state during teardown. Nothing is lost:
			// no receipt was sent, so control redelivers on reconnect.
			if workerCtx.Err() != nil {
				continue
			}
			c.runManifestDelivery(workerCtx, delivery, handler)
		}
	}()
	defer func() {
		c.mu.Lock()
		c.deliveryCh = nil
		c.mu.Unlock()
		cancelWorker()
		close(deliveryCh)
		deliveryWG.Wait()
	}()

	// Channel to receive messages from blocking Receive call
	type receiveResult struct {
		msg *pm.ServerMessage
		err error
	}
	msgCh := make(chan receiveResult, 1)

	// Start receive goroutine
	go func() {
		for {
			msg, err := c.Receive(ctx)
			select {
			case msgCh <- receiveResult{msg, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()

	// Process incoming messages
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case result := <-msgCh:
			if result.err != nil {
				return fmt.Errorf("receive: %w", result.err)
			}
			if err := c.dispatchServerMessage(ctx, result.msg, handler); err != nil {
				return err
			}
		}
	}
}

// applyWelcomeHeartbeat extracts the server-requested heartbeat
// interval from a Welcome message, clamps it to [MinHeartbeatInterval,
// MaxHeartbeatInterval], and pushes it to the running heartbeat
// goroutine. No-op when Welcome.heartbeat_interval is zero/unset or
// when no Run() is currently active. The update channel has capacity
// 1 and latest-wins semantics — a stale pending update is dropped so
// the goroutine always picks up the most recent value the server sent.
func (c *Client) applyWelcomeHeartbeat(w *pm.Welcome) {
	if w == nil || w.HeartbeatInterval == nil {
		return
	}
	d := w.HeartbeatInterval.AsDuration()
	if d <= 0 {
		return
	}
	if d < MinHeartbeatInterval {
		d = MinHeartbeatInterval
	}
	if d > MaxHeartbeatInterval {
		d = MaxHeartbeatInterval
	}
	c.mu.RLock()
	ch := c.heartbeatUpdate
	c.mu.RUnlock()
	if ch == nil {
		return
	}
	// Drain any stale pending value, then push the fresh one. Both
	// sends are non-blocking so a hung / exited heartbeat goroutine
	// can't wedge the dispatcher.
	select {
	case <-ch:
	default:
	}
	select {
	case ch <- d:
	default:
	}
}

// safeGo runs fn in a new goroutine with a deferred recover so a panic
// in a server-originated fan-out handler (inventory, LUKS revoke,
// inventory ticker) cannot crash the whole agent process. A panic in a
// goroutine is unrecoverable by the parent, so each spawned goroutine
// must guard itself. label identifies the leg in the log line.
func (c *Client) safeGo(label string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				c.logger.Error("recovered panic in stream dispatch goroutine",
					"leg", label, "panic", fmt.Sprintf("%v", r))
			}
		}()
		fn()
	}()
}

// dispatchServerMessage routes a single ServerMessage to the appropriate
// handler method. Extracted from Run for testability — call sites that
// need a fake stream or hand-built messages can drive this directly.
// Returns a non-nil error only for fatal stream errors that should tear
// down the connection; per-message handler failures (LUKS, terminal,
// etc.) are wrapped before returning so callers see what failed.
//
// The per-message body runs under a deferred recover(): a panic inside ANY
// handler method is caught, logged, and turned into a NON-fatal outcome
// (dispatch returns nil) so one buggy or hostile handler invocation cannot
// crash-loop the agent (Run treats a returned error as fatal and tears the
// connection down). Genuine fatal stream send/receive errors still return
// as errors — only handler PANICS become non-fatal.
// validateInbound runs the shared `validate` gotags on a concrete inbound
// command payload (WS13 #5) — defence-in-depth so a compromised relay can't push
// a malformed-but-non-nil frame (out-of-range PTY dims, non-ULID session id,
// empty action envelope) past the SDK boundary into a handler.
func (c *Client) validateInbound(payload any) error {
	if c.validator == nil {
		return nil
	}
	if msg, ok := validate.Struct(c.validator, payload); !ok {
		return errors.New(msg)
	}
	return nil
}

// currentDeliveryCh returns the per-Run delivery worker channel, or nil when
// Run() is not active (e.g. dispatchServerMessage driven directly by a unit
// test).
func (c *Client) currentDeliveryCh() chan *pm.ManifestDelivery {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.deliveryCh
}

// runManifestDelivery hands one delivery to the handler and, only if the
// handler reports it durably recorded, sends the DeliveryReceipt. Run on the
// single delivery worker goroutine (or inline as a test fallback).
//
// The receipt is sent here rather than by the handler so the ordering is
// structural: there is no code path that emits a receipt without a nil return
// from the handler, and none that returns nil without the handler having
// committed. A handler error or panic therefore leaves the delivery
// unacknowledged, which is the outcome that makes control redeliver.
func (c *Client) runManifestDelivery(ctx context.Context, delivery *pm.ManifestDelivery, handler StreamHandler) {
	defer func() {
		if r := recover(); r != nil {
			c.logger.Error("recovered panic while handling manifest delivery (non-fatal; no receipt sent)",
				"delivery_id", delivery.GetDeliveryId(), "panic", fmt.Sprintf("%v", r))
		}
	}()
	var err error
	if streamingHandler, ok := handler.(StreamingHandler); ok {
		sendChunk := func(chunk *pm.OutputChunk) error { return c.SendOutputChunk(ctx, chunk) }
		err = streamingHandler.OnManifestDeliveryWithStreaming(ctx, delivery, sendChunk)
	} else {
		err = handler.OnManifestDelivery(ctx, delivery)
	}
	if err != nil {
		// Not durably recorded: staying silent is the correct answer, because
		// control's retry is the only thing that recovers this delivery.
		c.logger.Error("manifest delivery not recorded; withholding receipt",
			"delivery_id", delivery.GetDeliveryId(), "error", err)
		return
	}
	if err := c.SendDeliveryReceipt(ctx, delivery.GetDeliveryId()); err != nil {
		c.logger.Warn("failed to send delivery receipt", "delivery_id", delivery.GetDeliveryId(), "error", err)
	}
}

func (c *Client) dispatchServerMessage(ctx context.Context, msg *pm.ServerMessage, handler StreamHandler) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			var payloadType string
			if msg != nil {
				payloadType = fmt.Sprintf("%T", msg.Payload)
			}
			var msgID string
			if msg != nil {
				msgID = msg.Id
			}
			c.logger.Error("recovered panic while dispatching ServerMessage; dropping frame (non-fatal)",
				"message_id", msgID, "payload_type", payloadType, "panic", fmt.Sprintf("%v", r))
			// Non-fatal: keep the receive loop alive.
			retErr = nil
		}
	}()
	switch p := msg.Payload.(type) {
	case *pm.ServerMessage_Welcome:
		if p.Welcome == nil {
			c.logger.Warn("dropping Welcome with nil payload", "message_id", msg.Id)
			return nil
		}
		c.applyWelcomeHeartbeat(p.Welcome)
		if err := handler.OnWelcome(ctx, p.Welcome); err != nil {
			return fmt.Errorf("handle welcome: %w", err)
		}

	case *pm.ServerMessage_ManifestDelivery:
		// Malformed-oneof guard: a buggy or hostile peer can deliver a
		// ServerMessage_ManifestDelivery whose inner message is nil, and
		// reading through it is a nil-pointer dereference. Drop non-fatally.
		if p.ManifestDelivery == nil {
			c.logger.Warn("dropping manifest delivery with nil payload", "message_id", msg.Id)
			return nil
		}
		if err := c.validateInbound(p.ManifestDelivery); err != nil {
			c.logger.Warn("dropping invalid manifest delivery", "message_id", msg.Id, "error", err)
			return nil
		}
		// Off-loop (WS13 #7): hand the delivery to the single per-Run worker so
		// recording and running a manifest can't head-of-line-block
		// TerminalStop/Input/Resize on the receive loop. The worker preserves
		// one-at-a-time, in-order handling and sends the receipt itself.
		if ch := c.currentDeliveryCh(); ch != nil {
			select {
			case ch <- p.ManifestDelivery:
			default:
				// A full queue means a pathological flood (a legit control never
				// has deliveryQueueDepth deliveries outstanding). Drop with a
				// loud warning rather than block the receive loop; no receipt
				// goes out, so control redelivers.
				c.logger.Warn("delivery queue full; dropping manifest delivery",
					"message_id", msg.Id, "delivery_id", p.ManifestDelivery.GetDeliveryId(), "depth", deliveryQueueDepth)
			}
			return nil
		}
		// Fallback: no worker (dispatchServerMessage driven directly, e.g. a unit
		// test, outside Run) — handle inline so behaviour is preserved.
		c.runManifestDelivery(ctx, p.ManifestDelivery, handler)

	case *pm.ServerMessage_Query:
		if p.Query == nil {
			c.logger.Warn("dropping Query with nil payload", "message_id", msg.Id)
			return nil
		}
		if err := c.validateInbound(p.Query); err != nil {
			c.logger.Warn("dropping invalid Query", "message_id", msg.Id, "error", err)
			return nil
		}
		queryResult, err := handler.OnQuery(ctx, p.Query)
		if err != nil {
			return fmt.Errorf("handle query: %w", err)
		}
		if queryResult != nil {
			if err := c.SendQueryResult(ctx, queryResult); err != nil {
				return fmt.Errorf("send query result: %w", err)
			}
		}

	case *pm.ServerMessage_Error:
		if p.Error == nil {
			c.logger.Warn("dropping Error with nil payload", "message_id", msg.Id)
			return nil
		}
		// A CORRELATED error is the rejection of a specific request, and its
		// caller is blocked waiting for exactly this message ID. Routing it to
		// the general handler instead left that caller waiting until its
		// context expired — with the server having already answered. The
		// operations that block here are the irreversible ones, so a rejection
		// they never receive stalls the rollback for the whole timeout.
		if c.deliverPending(msg) {
			return nil
		}
		// Uncorrelated: a server-originated error with no waiter.
		if err := handler.OnError(ctx, p.Error); err != nil {
			return fmt.Errorf("handle error: %w", err)
		}

	case *pm.ServerMessage_SyncState,
		*pm.ServerMessage_GetLuksKey,
		*pm.ServerMessage_StoreLuksKey,
		*pm.ServerMessage_StoreLpsPasswords,
		*pm.ServerMessage_ValidateLuksToken:
		// Correlated response: deliver to the pending request by message ID.
		// Every Client method that blocks on registerPending MUST be listed here
		// — a missing case does not error, it drops the frame and the caller
		// blocks until its context expires.
		//
		// This list being handwritten is a known weakness (a fourth waiter can
		// be added without a case). It is NOT fixed by correlating on the ID
		// before the switch: the inbound-validation guard classifies response
		// arms by seeing deliverPending in their case, so hoisting the
		// correlation reclassifies all three as command arms and demands
		// validateInbound on a path that only hands the message to its caller.
		// The fix belongs in the guard — discover the registerPending callers
		// and assert each has a case — not in the dispatch shape.
		c.deliverPending(msg)

	case *pm.ServerMessage_RequestInventory:
		if p.RequestInventory == nil {
			c.logger.Warn("dropping RequestInventory with nil payload", "message_id", msg.Id)
			return nil
		}
		if err := c.validateInbound(p.RequestInventory); err != nil {
			c.logger.Warn("dropping invalid RequestInventory", "message_id", msg.Id, "error", err)
			return nil
		}
		if invHandler, ok := handler.(InventoryHandler); ok {
			req := p.RequestInventory
			// Bound concurrency: drop (don't queue) when already at
			// capacity so a flood cannot spawn unbounded osquery forks.
			select {
			case c.invSem <- struct{}{}:
				// safeGo: a panic in OnRequestInventory runs in this spawned
				// goroutine and would otherwise crash the whole agent.
				c.safeGo("inventory", func() {
					defer func() { <-c.invSem }()
					// The handler may reject the request before running osquery.
					if inv := invHandler.OnRequestInventory(ctx, req); inv != nil {
						if err := c.SendInventory(ctx, inv); err != nil {
							c.logger.Warn("failed to send inventory", "error", err)
						}
					}
				})
			default:
				c.logger.Warn("dropping RequestInventory: inventory collection already at capacity",
					"message_id", msg.Id, "limit", inventoryDispatchConcurrency)
			}
		}

	case *pm.ServerMessage_LogQuery:
		if p.LogQuery == nil {
			c.logger.Warn("dropping LogQuery with nil payload", "message_id", msg.Id)
			return nil
		}
		if err := c.validateInbound(p.LogQuery); err != nil {
			c.logger.Warn("dropping invalid LogQuery", "message_id", msg.Id, "error", err)
			return nil
		}
		if lqHandler, ok := handler.(LogQueryHandler); ok {
			result, err := lqHandler.OnLogQuery(ctx, p.LogQuery)
			if err != nil {
				return fmt.Errorf("handle log query: %w", err)
			}
			if result != nil {
				if err := c.SendLogQueryResult(ctx, result); err != nil {
					return fmt.Errorf("send log query result: %w", err)
				}
			}
		}

	case *pm.ServerMessage_RevokeLuksDeviceKey:
		if p.RevokeLuksDeviceKey == nil {
			// A buggy server could deliver a nil payload; dropping it avoids
			// a nil dereference.
			c.logger.Warn("dropping RevokeLuksDeviceKey with nil payload", "message_id", msg.Id)
			return nil
		}
		// Defence-in-depth before the irreversible LUKS slot-7 wipe: reject a
		// malformed action_id at the SDK boundary.
		if err := c.validateInbound(p.RevokeLuksDeviceKey); err != nil {
			c.logger.Warn("dropping invalid RevokeLuksDeviceKey", "message_id", msg.Id, "error", err)
			return nil
		}
		if luksHandler, ok := handler.(LuksHandler); ok {
			req := p.RevokeLuksDeviceKey
			actionID := req.ActionId
			// Run in goroutine: the handler calls GetLuksKey which sends
			// a request on the stream and waits for a response. Processing
			// that response requires this receive loop to keep running.
			// Bound concurrency and drop overflow so a flood cannot spawn
			// unbounded goroutines (WS6 #11).
			select {
			case c.luksRevokeSem <- struct{}{}:
				// safeGo: a panic in OnRevokeLuksDeviceKey runs in this
				// spawned goroutine and would otherwise crash the agent.
				c.safeGo("luks-revoke", func() {
					defer func() { <-c.luksRevokeSem }()
					// Pass the full message so later request fields remain available.
					success, errMsg := luksHandler.OnRevokeLuksDeviceKey(ctx, req)
					if err := c.SendRevokeLuksDeviceKeyResult(ctx, actionID, success, errMsg); err != nil {
						c.logger.Warn("failed to send LUKS revocation result", "action_id", actionID, "error", err)
					}
				})
			default:
				c.logger.Warn("dropping RevokeLuksDeviceKey: revocation already at capacity",
					"message_id", msg.Id, "action_id", actionID, "limit", luksRevokeDispatchConcurrency)
			}
		}

	case *pm.ServerMessage_TerminalStart:
		if p.TerminalStart == nil {
			c.logger.Warn("dropping TerminalStart with nil payload", "message_id", msg.Id)
			return nil
		}
		if err := c.validateInbound(p.TerminalStart); err != nil {
			c.logger.Warn("dropping invalid TerminalStart", "message_id", msg.Id, "error", err)
			return nil
		}
		if termHandler, ok := handler.(TerminalHandler); ok {
			if err := termHandler.OnTerminalStart(ctx, p.TerminalStart); err != nil {
				return fmt.Errorf("handle terminal start: %w", err)
			}
		} else {
			c.logger.Debug("dropping TerminalStart: handler does not implement TerminalHandler",
				"session_id", p.TerminalStart.SessionId)
		}

	case *pm.ServerMessage_TerminalInput:
		if p.TerminalInput == nil {
			c.logger.Warn("dropping TerminalInput with nil payload", "message_id", msg.Id)
			return nil
		}
		if err := c.validateInbound(p.TerminalInput); err != nil {
			c.logger.Warn("dropping invalid TerminalInput", "message_id", msg.Id, "error", err)
			return nil
		}
		if termHandler, ok := handler.(TerminalHandler); ok {
			if err := termHandler.OnTerminalInput(ctx, p.TerminalInput); err != nil {
				return fmt.Errorf("handle terminal input: %w", err)
			}
		}

	case *pm.ServerMessage_TerminalResize:
		if p.TerminalResize == nil {
			c.logger.Warn("dropping TerminalResize with nil payload", "message_id", msg.Id)
			return nil
		}
		if err := c.validateInbound(p.TerminalResize); err != nil {
			c.logger.Warn("dropping invalid TerminalResize", "message_id", msg.Id, "error", err)
			return nil
		}
		if termHandler, ok := handler.(TerminalHandler); ok {
			if err := termHandler.OnTerminalResize(ctx, p.TerminalResize); err != nil {
				return fmt.Errorf("handle terminal resize: %w", err)
			}
		}

	case *pm.ServerMessage_TerminalStop:
		if p.TerminalStop == nil {
			c.logger.Warn("dropping TerminalStop with nil payload", "message_id", msg.Id)
			return nil
		}
		if err := c.validateInbound(p.TerminalStop); err != nil {
			c.logger.Warn("dropping invalid TerminalStop", "message_id", msg.Id, "error", err)
			return nil
		}
		if termHandler, ok := handler.(TerminalHandler); ok {
			if err := termHandler.OnTerminalStop(ctx, p.TerminalStop); err != nil {
				return fmt.Errorf("handle terminal stop: %w", err)
			}
		}

	default:
		// Forward-compat: a newer server may add a ServerMessage
		// payload variant that this SDK build does not yet recognise.
		// Logging at debug keeps this observable without spamming
		// production logs, and we deliberately do NOT return an error
		// — that would tear down the agent connection on every
		// unknown frame, which is much worse than silently dropping it.
		c.logger.Debug("dropping unknown ServerMessage payload",
			"message_id", msg.Id, "type", fmt.Sprintf("%T", msg.Payload))
	}
	return nil
}

// NewULID generates a new ULID string.
func NewULID() string {
	return ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
}

// DeviceID returns the current device ID.
func (c *Client) DeviceID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.deviceID
}

// AuthToken returns the current auth token.
func (c *Client) AuthToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.authToken
}

// ValidateLuksTokenResult contains the result of a LUKS token validation.
type ValidateLuksTokenResult struct {
	ActionID   string
	DevicePath string
	MinLength  int32
	Complexity pm.LpsPasswordComplexity
}

// ValidateLuksToken validates and atomically consumes a one-time LUKS token on
// the existing authenticated agent stream.
func (c *Client) ValidateLuksToken(ctx context.Context, token string) (*ValidateLuksTokenResult, error) {
	id := NewULID()
	ch := c.registerPending(id)
	defer c.unregisterPending(id)
	if err := c.send(ctx, &pm.AgentMessage{
		Id: id,
		Payload: &pm.AgentMessage_ValidateLuksToken{
			ValidateLuksToken: &pm.ValidateLuksTokenRequest{Token: token},
		},
	}); err != nil {
		return nil, fmt.Errorf("send validate luks token request: %w", err)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case response, ok := <-ch:
		if !ok || response == nil {
			return nil, errors.New("stream closed while waiting for ValidateLuksToken response")
		}
		if errorMessage := response.GetError(); errorMessage != nil {
			return nil, fmt.Errorf("server error: %s", errorMessage.Message)
		}
		validated := response.GetValidateLuksToken()
		if validated == nil {
			return nil, errors.New("unexpected response type")
		}
		if err := c.validateInbound(validated); err != nil {
			return nil, fmt.Errorf("invalid ValidateLuksToken response: %w", err)
		}
		return &ValidateLuksTokenResult{
			ActionID:   validated.ActionId,
			DevicePath: validated.DevicePath,
			MinLength:  validated.MinLength,
			Complexity: validated.Complexity,
		}, nil
	}
}

// SyncStateResult contains the current device state returned over the stream.
type SyncStateResult struct {
	// Deliveries are every manifest delivery currently assigned to this
	// device, in exactly the form the stream pushes them. The caller records
	// each one under its delivery_id and receipts it the same way, so a
	// delivery already known from the stream is recognised as a repeat rather
	// than executed twice.
	Deliveries []*pm.ManifestDelivery
	// SyncIntervalMinutes is the effective sync interval for this device.
	// 0 means use the default (30 minutes).
	SyncIntervalMinutes int32
	// MaintenanceWindow is the server-resolved union of every reaching
	// group's window (device groups + user groups assigned to the
	// device). nil means "no constraint" — the agent dispatches at any
	// time. The agent evaluates this against time.Now().Local() before
	// firing scheduler-driven dispatches; instant actions bypass the gate.
	MaintenanceWindow *pm.MaintenanceWindow
}

// Sync requests the current deliveries and device policy on the existing
// stream. The caller records every delivery before sending its receipt.
func (c *Client) Sync(ctx context.Context) (*SyncStateResult, error) {
	id := NewULID()
	ch := c.registerPending(id)
	defer c.unregisterPending(id)
	if err := c.send(ctx, &pm.AgentMessage{
		Id:      id,
		Payload: &pm.AgentMessage_SyncRequest{SyncRequest: &pm.SyncRequest{}},
	}); err != nil {
		return nil, fmt.Errorf("send sync request: %w", err)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case response, ok := <-ch:
		if !ok || response == nil {
			return nil, errors.New("stream closed while waiting for SyncState response")
		}
		if errorMessage := response.GetError(); errorMessage != nil {
			return nil, fmt.Errorf("server error: %s", errorMessage.Message)
		}
		state := response.GetSyncState()
		if state == nil {
			return nil, errors.New("unexpected response type")
		}
		if err := c.validateInbound(state); err != nil {
			return nil, fmt.Errorf("invalid SyncState response: %w", err)
		}
		return &SyncStateResult{
			Deliveries:          state.Deliveries,
			SyncIntervalMinutes: state.SyncIntervalMinutes,
			MaintenanceWindow:   state.MaintenanceWindow,
		}, nil
	}
}
