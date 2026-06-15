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

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/sdk/go/validate"
)

// Heartbeat interval bounds. The SDK clamps server-supplied values from
// Welcome.heartbeat_interval into this range before applying them, so a
// misconfigured or malicious server can never push the cadence outside
// what's safe for both sides (too fast = stream spam, too slow = agent
// looks dead to the gateway's liveness tracking).
const (
	MinHeartbeatInterval = 5 * time.Second
	MaxHeartbeatInterval = 5 * time.Minute
)

// Client provides methods to communicate with the power-manage server.
type Client struct {
	client    pmv1connect.AgentServiceClient
	deviceID  string
	authToken string
	logger    *slog.Logger

	// httpClient is the underlying transport carrier, retained so the agent
	// can release its idle connections on reconnect (CloseIdleConnections) and
	// not leak a transport per reconnect attempt (WS13 #8).
	httpClient *http.Client

	// validator enforces the inbound `validate` gotags on each server command
	// before dispatch (WS13 #5) — defence-in-depth against a compromised relay
	// pushing a malformed-but-non-nil frame. Created in NewClient.
	validator *validator.Validate

	mu     sync.RWMutex
	stream *connect.BidiStreamForClient[pm.AgentMessage, pm.ServerMessage]

	// actionCh feeds the per-Run action worker. Server-dispatched actions are
	// handed to a single worker goroutine (off the receive loop) so a
	// long-running action can no longer head-of-line-block TerminalStop/Input/
	// Resize (WS13 #7). A single worker preserves one-at-a-time, in-order
	// execution; the buffered channel bounds memory. Non-nil only while Run()
	// is active; guarded by mu.
	actionCh chan *pm.ActionDispatch

	// sendMu serializes all stream.Send() calls — concurrent writes on a
	// bidi stream are not safe and can corrupt messages on the wire.
	sendMu sync.Mutex

	// pendingMu protects pendingRequests for LUKS request-response correlation.
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
	// compromised or buggy gateway could exhaust memory and goroutines.
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
	// size. Without a bound, a compromised or buggy gateway could push a
	// multi-gigabyte frame and force the agent to allocate it, an OOM /
	// DoS vector. 16 MiB is comfortably above any real frame yet refuses
	// a frame whose only purpose is to exhaust memory. Enforced via
	// connect.WithReadMaxBytes in NewClient; the connection that receives
	// an oversized frame is torn down with a resource-exhausted error.
	maxInboundMessageBytes = 16 << 20 // 16 MiB

	// actionQueueDepth bounds how many server-dispatched actions can wait for
	// the single action worker (WS13 #7). Deep enough to absorb any legitimate
	// burst; a backlog beyond it means a pathological flood, so the excess is
	// dropped (the server re-dispatches on reconnect) rather than queued
	// unbounded or allowed to block the receive loop.
	actionQueueDepth = 256
)

// NewClient creates a new SDK client.
func NewClient(serverURL string, opts ...ClientOption) *Client {
	c := &Client{
		logger:        slog.Default(),
		validator:     validate.NewValidator(),
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
	// gateway could otherwise push an arbitrarily large frame and force
	// the agent to allocate it (OOM/DoS). connect.WithReadMaxBytes makes
	// the connection that receives an oversized frame fail with a
	// resource-exhausted error and tear down cleanly, rather than
	// allocate. The long-lived bidi stream is unaffected for normal
	// (small) control frames.
	c.client = pmv1connect.NewAgentServiceClient(httpClient, serverURL,
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
// internal-CA-signed gateway over mTLS — system roots are NOT
// consulted, so a cert signed by any public CA cannot impersonate
// the gateway even if its SNI matches.
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
// Do NOT use this for the agent-to-gateway mTLS connection: the
// gateway is internal-CA only, and broadening its trust to system
// roots lets any publicly-trusted cert with a matching SNI
// impersonate the gateway.
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
// see why the agent is unable to reach the gateway.
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
	GatewayURL  string
}

// RegisterAgent registers an agent with the control server.
// This is a standalone function that uses ControlServiceClient (not AgentServiceClient).
// The controlURL is the control server URL (where the web UI connects).
// Returns the gateway URL that the agent should use for streaming.
func RegisterAgent(ctx context.Context, controlURL string, token, hostname, agentVersion string, csr []byte, opts ...ClientOption) (*RegisterAgentResult, error) {
	c := &Client{}
	httpClient := bootstrapHTTPClient()
	for _, opt := range opts {
		opt.apply(c, &httpClient)
	}

	controlClient := pmv1connect.NewControlServiceClient(httpClient, controlURL)

	req := connect.NewRequest(&pm.RegisterRequest{
		Token:        token,
		Hostname:     hostname,
		AgentVersion: agentVersion,
		Csr:          csr,
	})

	resp, err := controlClient.Register(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}

	return &RegisterAgentResult{
		DeviceID:    resp.Msg.DeviceId.GetValue(),
		CACert:      resp.Msg.CaCert,
		Certificate: resp.Msg.Certificate,
		GatewayURL:  resp.Msg.GatewayUrl,
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

	controlClient := pmv1connect.NewControlServiceClient(httpClient, controlURL)

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
	// OnAction is called when the server dispatches an action. The handler
	// receives the signed envelope bytes and the CA signature: it MUST
	// verify the signature over `envelope` and unmarshal THOSE SAME bytes
	// (a pm.SignedActionEnvelope) to execute — the executed action is the
	// verified action (sdk#82).
	OnAction(ctx context.Context, envelope []byte, signature []byte) (*pm.ActionResult, error)
	// OnQuery is called when the server sends an OS query.
	OnQuery(ctx context.Context, query *pm.OSQuery) (*pm.OSQueryResult, error)
	// OnError is called when the server sends an error.
	OnError(ctx context.Context, err *pm.Error) error
}

// StreamingHandler extends StreamHandler with streaming action support.
// Handlers that implement this interface will receive a callback to stream
// output chunks during action execution.
type StreamingHandler interface {
	StreamHandler
	// OnActionWithStreaming is called when the server dispatches an action.
	// It receives the signed envelope bytes and CA signature (verify-then-
	// unmarshal-then-execute the SAME bytes; see OnAction). The sendChunk
	// callback streams output chunks during execution.
	OnActionWithStreaming(ctx context.Context, envelope []byte, signature []byte, sendChunk func(*pm.OutputChunk) error) (*pm.ActionResult, error)
}

// LuksHandler extends StreamHandler with LUKS device-key revocation support.
// Handlers that implement this interface will receive revoke requests from the server.
type LuksHandler interface {
	StreamHandler
	// OnRevokeLuksDeviceKey is called when the server requests revocation of a
	// LUKS device-bound key. The full message is delivered (not just the
	// action_id) so the handler can verify the CA signature that binds it
	// before performing the destructive, irreversible slot-7 wipe.
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
	// the agent's OWN schedule (on connect + every 24h). This is the
	// agent-initiated path: no server command is involved, so no signature is
	// required. Returns nil if collection is unavailable (e.g. osquery not
	// installed).
	CollectInventory(ctx context.Context) *pm.DeviceInventory
	// OnRequestInventory handles a SERVER-originated RequestInventory. Because
	// a compromised gateway could forge this message, the handler verifies the
	// CA signature that binds it before running osquery as root, then collects
	// the same inventory. Returns nil on verification failure or when
	// collection is unavailable.
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

// send serializes all writes to the bidirectional stream.
// Multiple goroutines (heartbeat, inventory, result sender) may call Send
// methods concurrently; without serialization this can corrupt messages.
func (c *Client) send(msg *pm.AgentMessage) error {
	c.mu.RLock()
	stream := c.stream
	c.mu.RUnlock()

	if stream == nil {
		return errors.New("not connected")
	}

	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return stream.Send(msg)
}

// SendHello sends a hello message to the server.
func (c *Client) SendHello(ctx context.Context, hostname, agentVersion string) error {
	c.mu.RLock()
	deviceID := c.deviceID
	authToken := c.authToken
	c.mu.RUnlock()

	return c.send(&pm.AgentMessage{
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
	return c.send(&pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_Heartbeat{
			Heartbeat: hb,
		},
	})
}

// SendActionResult sends an action result to the server.
func (c *Client) SendActionResult(ctx context.Context, result *pm.ActionResult) error {
	return c.send(&pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_ActionResult{
			ActionResult: result,
		},
	})
}

// SendOutputChunk sends an output chunk during action execution.
func (c *Client) SendOutputChunk(ctx context.Context, chunk *pm.OutputChunk) error {
	return c.send(&pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_OutputChunk{
			OutputChunk: chunk,
		},
	})
}

// SendQueryResult sends an OS query result to the server.
func (c *Client) SendQueryResult(ctx context.Context, result *pm.OSQueryResult) error {
	return c.send(&pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_QueryResult{
			QueryResult: result,
		},
	})
}

// SendLogQueryResult sends a log query result to the server.
func (c *Client) SendLogQueryResult(ctx context.Context, result *pm.LogQueryResult) error {
	return c.send(&pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_LogQueryResult{
			LogQueryResult: result,
		},
	})
}

// SendSecurityAlert sends a security alert to the server for audit logging.
func (c *Client) SendSecurityAlert(ctx context.Context, alert *pm.SecurityAlert) error {
	return c.send(&pm.AgentMessage{
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

	return c.send(&pm.AgentMessage{
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
	return c.send(&pm.AgentMessage{
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
	return c.send(&pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_TerminalStateChange{
			TerminalStateChange: change,
		},
	})
}

// GetLuksKey sends a GetLuksKeyRequest on the stream and waits for the correlated response.
// The response is matched by the message ID.
func (c *Client) GetLuksKey(ctx context.Context, actionID string) (string, error) {
	id := NewULID()
	ch := c.registerPending(id)
	defer c.unregisterPending(id)

	if err := c.send(&pm.AgentMessage{
		Id: id,
		Payload: &pm.AgentMessage_GetLuksKey{
			GetLuksKey: &pm.GetLuksKeyRequest{
				ActionId: actionID,
			},
		},
	}); err != nil {
		return "", fmt.Errorf("send get luks key request: %w", err)
	}

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case resp := <-ch:
		if errMsg := resp.GetError(); errMsg != nil {
			return "", fmt.Errorf("server error: %s", errMsg.Message)
		}
		luksResp := resp.GetGetLuksKey()
		if luksResp == nil {
			return "", errors.New("unexpected response type")
		}
		return luksResp.Passphrase, nil
	}
}

// StoreLuksKey sends a StoreLuksKeyRequest on the stream and waits for the server confirmation.
func (c *Client) StoreLuksKey(ctx context.Context, actionID, devicePath, passphrase string, reason pm.RotationReason) error {
	id := NewULID()
	ch := c.registerPending(id)
	defer c.unregisterPending(id)

	if err := c.send(&pm.AgentMessage{
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
	case resp := <-ch:
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

// SendRevokeLuksDeviceKeyResult sends the result of a LUKS device key revocation back to the server.
func (c *Client) SendRevokeLuksDeviceKeyResult(ctx context.Context, actionID string, success bool, errMsg string) error {
	return c.send(&pm.AgentMessage{
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

// Close closes the stream connection and cancels any pending LUKS requests.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stream == nil {
		return nil
	}

	// Cancel pending LUKS requests
	c.pendingMu.Lock()
	for id, ch := range c.pendingRequests {
		close(ch)
		delete(c.pendingRequests, id)
	}
	c.pendingMu.Unlock()

	// Close both request and response sides of the stream
	c.stream.CloseRequest()
	c.stream.CloseResponse()
	c.stream = nil
	return nil
}

// StartReceiver starts a background goroutine that receives stream messages and
// delivers them to pending request channels (for GetLuksKey/StoreLuksKey responses).
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
	defer c.Close()

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

	// Action worker (WS13 #7): server-dispatched actions execute on this single
	// goroutine, off the receive loop, so a long-running action cannot
	// head-of-line-block terminal control frames. One worker = one-at-a-time,
	// in-order execution; the buffered channel bounds memory. Published on the
	// Client so dispatchServerMessage can enqueue; cleared + drained on Run exit.
	actionCh := make(chan *pm.ActionDispatch, actionQueueDepth)
	workerCtx, cancelWorker := context.WithCancel(ctx)
	c.mu.Lock()
	c.actionCh = actionCh
	c.mu.Unlock()
	var actionWG sync.WaitGroup
	actionWG.Add(1)
	go func() {
		defer actionWG.Done()
		for disp := range actionCh {
			// Skip queued actions once the connection is going down rather than
			// half-applying system state during teardown; the server
			// re-dispatches unacked actions on reconnect.
			if workerCtx.Err() != nil {
				continue
			}
			c.runDispatchedAction(workerCtx, disp, handler)
		}
	}()
	defer func() {
		c.mu.Lock()
		c.actionCh = nil
		c.mu.Unlock()
		cancelWorker()
		close(actionCh)
		actionWG.Wait()
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

// currentActionCh returns the per-Run action worker channel, or nil when Run()
// is not active (e.g. dispatchServerMessage driven directly by a unit test).
func (c *Client) currentActionCh() chan *pm.ActionDispatch {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.actionCh
}

// runDispatchedAction executes one server-dispatched action and sends its
// result. Run on the single action worker goroutine (or inline as a test
// fallback). A panic is recovered (one bad action can't crash the agent); an
// infrastructure error is logged, not propagated — off the receive loop there is
// no connection to tear down, and an action *failure* already comes back as a
// FAILED ActionResult rather than an error.
func (c *Client) runDispatchedAction(ctx context.Context, disp *pm.ActionDispatch, handler StreamHandler) {
	defer func() {
		if r := recover(); r != nil {
			c.logger.Error("recovered panic while executing dispatched action (non-fatal)", "panic", fmt.Sprintf("%v", r))
		}
	}()
	var result *pm.ActionResult
	var err error
	if streamingHandler, ok := handler.(StreamingHandler); ok {
		sendChunk := func(chunk *pm.OutputChunk) error { return c.SendOutputChunk(ctx, chunk) }
		result, err = streamingHandler.OnActionWithStreaming(ctx, disp.Envelope, disp.Signature, sendChunk)
	} else {
		result, err = handler.OnAction(ctx, disp.Envelope, disp.Signature)
	}
	if err != nil {
		c.logger.Error("action handler error", "error", err)
		return
	}
	if result != nil {
		if err := c.SendActionResult(ctx, result); err != nil {
			c.logger.Warn("failed to send action result", "error", err)
		}
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

	case *pm.ServerMessage_Action:
		// Malformed-oneof guard: a compromised/buggy gateway could deliver a
		// ServerMessage_Action whose inner ActionDispatch is nil. Reading
		// p.Action.Envelope/.Signature on a nil p.Action is a nil-pointer
		// dereference. Drop it non-fatally — every real Action on the wire
		// carries the signed envelope + signature.
		if p.Action == nil {
			c.logger.Warn("dropping Action with nil dispatch payload", "message_id", msg.Id)
			return nil
		}
		if err := c.validateInbound(p.Action); err != nil {
			c.logger.Warn("dropping invalid Action", "message_id", msg.Id, "error", err)
			return nil
		}
		// Off-loop (WS13 #7): hand the action to the single per-Run worker so a
		// long-running action can't head-of-line-block TerminalStop/Input/Resize
		// on the receive loop. The worker preserves one-at-a-time, in-order
		// execution and sends the result via the sendMu-serialized SendActionResult.
		if ch := c.currentActionCh(); ch != nil {
			select {
			case ch <- p.Action:
			default:
				// A full queue means a pathological flood (a legit gateway never
				// has actionQueueDepth actions outstanding). Drop with a loud
				// warning rather than block the receive loop; the server
				// re-dispatches unacked actions on reconnect.
				c.logger.Warn("action queue full; dropping dispatched action", "message_id", msg.Id, "depth", actionQueueDepth)
			}
			return nil
		}
		// Fallback: no worker (dispatchServerMessage driven directly, e.g. a unit
		// test, outside Run) — execute inline so behaviour is preserved.
		c.runDispatchedAction(ctx, p.Action, handler)

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
		if err := handler.OnError(ctx, p.Error); err != nil {
			return fmt.Errorf("handle error: %w", err)
		}

	case *pm.ServerMessage_GetLuksKey, *pm.ServerMessage_StoreLuksKey:
		// LUKS request-response: deliver to pending request by message ID.
		c.deliverPending(msg)

	case *pm.ServerMessage_RequestInventory:
		if invHandler, ok := handler.(InventoryHandler); ok {
			if p.RequestInventory == nil {
				c.logger.Warn("dropping RequestInventory with nil payload", "message_id", msg.Id)
				return nil
			}
			req := p.RequestInventory
			// Bound concurrency: drop (don't queue) when already at
			// capacity so a flood cannot spawn unbounded osquery forks.
			select {
			case c.invSem <- struct{}{}:
				// safeGo: a panic in OnRequestInventory runs in this spawned
				// goroutine and would otherwise crash the whole agent.
				c.safeGo("inventory", func() {
					defer func() { <-c.invSem }()
					// Server-originated: verify the signature (inside the
					// handler) before collecting. A forged RequestInventory
					// from a compromised gateway yields nil and never runs
					// osquery.
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
		if luksHandler, ok := handler.(LuksHandler); ok {
			req := p.RevokeLuksDeviceKey
			if req == nil {
				// A compromised/buggy gateway could deliver a nil payload;
				// dropping it avoids a nil dereference and is harmless (a
				// real revocation always carries action_id + signature).
				c.logger.Warn("dropping RevokeLuksDeviceKey with nil payload", "message_id", msg.Id)
				return nil
			}
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
					// Pass the full message so the handler can verify the CA
					// signature binding action_id before the destructive wipe.
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

// ValidateLuksToken validates a one-time LUKS token via the gateway's unary RPC.
// The token is consumed (marked as used) atomically by the server.
func (c *Client) ValidateLuksToken(ctx context.Context, token string) (*ValidateLuksTokenResult, error) {
	c.mu.RLock()
	deviceID := c.deviceID
	c.mu.RUnlock()

	if deviceID == "" {
		return nil, errors.New("device ID not set")
	}

	req := connect.NewRequest(&pm.ValidateLuksTokenRequest{
		DeviceId: deviceID,
		Token:    token,
	})

	resp, err := c.client.ValidateLuksToken(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("validate luks token: %w", err)
	}

	return &ValidateLuksTokenResult{
		ActionID:   resp.Msg.ActionId,
		DevicePath: resp.Msg.DevicePath,
		MinLength:  resp.Msg.MinLength,
		Complexity: resp.Msg.Complexity,
	}, nil
}

// SyncActionsResult contains the result of a sync actions call.
type SyncActionsResult struct {
	// StandaloneActions are actions assigned at the action layer (not absorbed
	// by a reached set or definition). Each fires on its own schedule.
	StandaloneActions []*pm.Action
	// GroupedActions are sets/definitions reaching this device, expressed as
	// groups that share a single schedule. Members run in declared order when
	// the group's schedule fires.
	GroupedActions []*pm.ActionGroup
	// SyncIntervalMinutes is the effective sync interval for this device.
	// 0 means use the default (30 minutes).
	SyncIntervalMinutes int32
	// MaintenanceWindow is the server-resolved union of every reaching
	// group's window (device groups + user groups assigned to the
	// device). nil means "no constraint" — the agent dispatches at any
	// time. The agent evaluates this against time.Now().Local() before
	// firing scheduler-driven dispatches; pushed actions (REBOOT,
	// SYNC, ad-hoc) bypass the gate. See manchtools/power-manage-server#58.
	MaintenanceWindow *pm.MaintenanceWindow
}

// SyncActions fetches all actions currently assigned to this device from the server.
// This should be called after a successful connection to sync the local action store.
// The returned actions should replace the agent's local action store entirely.
// Also returns the effective sync interval for this device.
func (c *Client) SyncActions(ctx context.Context) (*SyncActionsResult, error) {
	c.mu.RLock()
	deviceID := c.deviceID
	c.mu.RUnlock()

	if deviceID == "" {
		return nil, errors.New("device ID not set")
	}

	req := connect.NewRequest(&pm.SyncActionsRequest{
		DeviceId: &pm.DeviceId{Value: deviceID},
	})

	resp, err := c.client.SyncActions(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("sync actions: %w", err)
	}

	return &SyncActionsResult{
		StandaloneActions:   resp.Msg.StandaloneActions,
		GroupedActions:      resp.Msg.GroupedActions,
		SyncIntervalMinutes: resp.Msg.SyncIntervalMinutes,
		MaintenanceWindow:   resp.Msg.MaintenanceWindow,
	}, nil
}
