// Package sdk provides a client library for communicating with the power-manage server.
package sdk

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"
	"golang.org/x/net/http2"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
)

// Client provides methods to communicate with the power-manage server.
type Client struct {
	client    pmv1connect.AgentServiceClient
	deviceID  string
	authToken string

	mu     sync.RWMutex
	stream *connect.BidiStreamForClient[pm.AgentMessage, pm.ServerMessage]

	// sendMu serializes all stream.Send() calls — concurrent writes on a
	// bidi stream are not safe and can corrupt messages on the wire.
	sendMu sync.Mutex

	// pendingMu protects pendingRequests for LUKS request-response correlation.
	pendingMu       sync.Mutex
	pendingRequests map[string]chan *pm.ServerMessage
}

// NewClient creates a new SDK client.
func NewClient(serverURL string, opts ...ClientOption) *Client {
	c := &Client{}

	httpClient := http.DefaultClient
	for _, opt := range opts {
		opt.apply(c, &httpClient)
	}

	c.client = pmv1connect.NewAgentServiceClient(httpClient, serverURL)
	return c
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
// This is useful when certificates are stored in memory (e.g., from registration response).
func WithMTLSFromPEM(certPEM, keyPEM, caPEM []byte) (ClientOption, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse client certificate: %w", err)
	}

	// Start from system roots so we also trust publicly-issued certificates
	// (e.g. Let's Encrypt on a reverse proxy), then add the internal CA.
	caPool, err := x509.SystemCertPool()
	if err != nil {
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

// WithInsecureSkipVerify disables TLS certificate verification.
// WARNING: Only use this for development/testing!
func WithInsecureSkipVerify() ClientOption {
	return &funcOption{func(c *Client, httpClient **http.Client) {
		*httpClient = newHTTPClientWithTLS(&tls.Config{
			InsecureSkipVerify: true,
		})
	}}
}

// newHTTPClientWithTLS creates an HTTP client with HTTP/2 support enabled.
// A bare http.Transport with a custom TLSClientConfig disables Go's automatic
// HTTP/2 negotiation, so we explicitly configure it via http2.ConfigureTransport.
func newHTTPClientWithTLS(tlsConfig *tls.Config) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	http2.ConfigureTransport(transport)
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
	httpClient := http.DefaultClient
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
	httpClient := http.DefaultClient
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
	// OnAction is called when the server dispatches an action.
	OnAction(ctx context.Context, action *pm.Action) (*pm.ActionResult, error)
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
	// The sendChunk callback can be used to stream output chunks during execution.
	OnActionWithStreaming(ctx context.Context, action *pm.Action, sendChunk func(*pm.OutputChunk) error) (*pm.ActionResult, error)
}

// LuksHandler extends StreamHandler with LUKS device-key revocation support.
// Handlers that implement this interface will receive revoke requests from the server.
type LuksHandler interface {
	StreamHandler
	// OnRevokeLuksDeviceKey is called when the server requests revocation of a LUKS device-bound key.
	// Returns (success, errorMessage).
	OnRevokeLuksDeviceKey(ctx context.Context, actionID string) (bool, string)
}

// InventoryHandler extends StreamHandler with device inventory collection support.
// Handlers that implement this interface can collect and send hardware/software inventory.
type InventoryHandler interface {
	StreamHandler
	// CollectInventory gathers hardware/software inventory from the device.
	// Returns nil if inventory collection is not available (e.g., osquery not installed).
	CollectInventory(ctx context.Context) *pm.DeviceInventory
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
func (c *Client) StoreLuksKey(ctx context.Context, actionID, devicePath, passphrase, reason string) error {
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
func (c *Client) deliverPending(msg *pm.ServerMessage) bool {
	c.pendingMu.Lock()
	ch, ok := c.pendingRequests[msg.Id]
	c.pendingMu.Unlock()
	if ok {
		select {
		case ch <- msg:
		default:
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

	go func() {
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()

		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				hb := &pm.Heartbeat{}
				// Handler can populate heartbeat data if needed
				if err := c.SendHeartbeat(heartbeatCtx, hb); err != nil {
					return
				}
			}
		}
	}()

	// Inventory: send on connect + every 24 hours
	if invHandler, ok := handler.(InventoryHandler); ok {
		go func() {
			// Initial inventory on connect
			if inv := invHandler.CollectInventory(heartbeatCtx); inv != nil {
				_ = c.SendInventory(heartbeatCtx, inv)
			}

			ticker := time.NewTicker(24 * time.Hour)
			defer ticker.Stop()

			for {
				select {
				case <-heartbeatCtx.Done():
					return
				case <-ticker.C:
					if inv := invHandler.CollectInventory(heartbeatCtx); inv != nil {
						_ = c.SendInventory(heartbeatCtx, inv)
					}
				}
			}
		}()
	}

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

			switch p := result.msg.Payload.(type) {
			case *pm.ServerMessage_Welcome:
				if err := handler.OnWelcome(ctx, p.Welcome); err != nil {
					return fmt.Errorf("handle welcome: %w", err)
				}

			case *pm.ServerMessage_Action:
				var actionResult *pm.ActionResult
				var err error

				// Check if handler supports streaming
				if streamingHandler, ok := handler.(StreamingHandler); ok {
					// Create a callback that sends output chunks
					sendChunk := func(chunk *pm.OutputChunk) error {
						return c.SendOutputChunk(ctx, chunk)
					}
					actionResult, err = streamingHandler.OnActionWithStreaming(ctx, p.Action.Action, sendChunk)
				} else {
					actionResult, err = handler.OnAction(ctx, p.Action.Action)
				}

				if err != nil {
					return fmt.Errorf("handle action: %w", err)
				}
				if actionResult != nil {
					if err := c.SendActionResult(ctx, actionResult); err != nil {
						return fmt.Errorf("send action result: %w", err)
					}
				}

			case *pm.ServerMessage_Query:
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
				if err := handler.OnError(ctx, p.Error); err != nil {
					return fmt.Errorf("handle error: %w", err)
				}

			case *pm.ServerMessage_GetLuksKey, *pm.ServerMessage_StoreLuksKey:
				// LUKS request-response: deliver to pending request by message ID.
				c.deliverPending(result.msg)

			case *pm.ServerMessage_RequestInventory:
				if invHandler, ok := handler.(InventoryHandler); ok {
					go func() {
						if inv := invHandler.CollectInventory(ctx); inv != nil {
							_ = c.SendInventory(ctx, inv)
						}
					}()
				}

			case *pm.ServerMessage_RevokeLuksDeviceKey:
				if luksHandler, ok := handler.(LuksHandler); ok {
					actionID := p.RevokeLuksDeviceKey.ActionId
					// Run in goroutine: the handler calls GetLuksKey which sends
					// a request on the stream and waits for a response. Processing
					// that response requires this receive loop to keep running.
					go func() {
						success, errMsg := luksHandler.OnRevokeLuksDeviceKey(ctx, actionID)
						_ = c.SendRevokeLuksDeviceKeyResult(ctx, actionID, success, errMsg)
					}()
				}
			}
		}
	}
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
	// Actions is the list of actions currently assigned to this device
	Actions []*pm.Action
	// SyncIntervalMinutes is the effective sync interval for this device.
	// 0 means use the default (30 minutes).
	SyncIntervalMinutes int32
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
		Actions:             resp.Msg.Actions,
		SyncIntervalMinutes: resp.Msg.SyncIntervalMinutes,
	}, nil
}
