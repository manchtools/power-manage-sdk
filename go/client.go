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
		*httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
	}}, nil
}

// WithTLSConfig configures the client with a custom TLS configuration.
func WithTLSConfig(tlsConfig *tls.Config) ClientOption {
	return &funcOption{func(c *Client, httpClient **http.Client) {
		*httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
	}}
}

// WithMTLSFromPEM configures mTLS using PEM-encoded certificate data.
// This is useful when certificates are stored in memory (e.g., from registration response).
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
		*httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
	}}, nil
}

// WithInsecureSkipVerify disables TLS certificate verification.
// WARNING: Only use this for development/testing!
func WithInsecureSkipVerify() ClientOption {
	return &funcOption{func(c *Client, httpClient **http.Client) {
		*httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	}}
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

// Register registers a new agent with the server.
// The csr parameter should be a PEM-encoded PKCS#10 Certificate Signing Request.
// The agent generates its own key pair and sends only the CSR; the private key never leaves the agent.
func (c *Client) Register(ctx context.Context, token, hostname, agentVersion string, csr []byte) (*pm.RegisterResponse, error) {
	req := connect.NewRequest(&pm.RegisterRequest{
		Token:        token,
		Hostname:     hostname,
		AgentVersion: agentVersion,
		Csr:          csr,
	})

	resp, err := c.client.Register(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}

	c.mu.Lock()
	c.deviceID = resp.Msg.DeviceId.Value
	c.authToken = resp.Msg.AuthToken
	c.mu.Unlock()

	return resp.Msg, nil
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

// SendHello sends a hello message to the server.
func (c *Client) SendHello(ctx context.Context, hostname, agentVersion string) error {
	c.mu.RLock()
	stream := c.stream
	deviceID := c.deviceID
	authToken := c.authToken
	c.mu.RUnlock()

	if stream == nil {
		return errors.New("not connected")
	}

	msg := &pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_Hello{
			Hello: &pm.Hello{
				DeviceId:     &pm.DeviceId{Value: deviceID},
				AgentVersion: agentVersion,
				Hostname:     hostname,
				AuthToken:    authToken,
			},
		},
	}

	return stream.Send(msg)
}

// SendHeartbeat sends a heartbeat message to the server.
func (c *Client) SendHeartbeat(ctx context.Context, hb *pm.Heartbeat) error {
	c.mu.RLock()
	stream := c.stream
	c.mu.RUnlock()

	if stream == nil {
		return errors.New("not connected")
	}

	msg := &pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_Heartbeat{
			Heartbeat: hb,
		},
	}

	return stream.Send(msg)
}

// SendActionResult sends an action result to the server.
func (c *Client) SendActionResult(ctx context.Context, result *pm.ActionResult) error {
	c.mu.RLock()
	stream := c.stream
	c.mu.RUnlock()

	if stream == nil {
		return errors.New("not connected")
	}

	msg := &pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_ActionResult{
			ActionResult: result,
		},
	}

	return stream.Send(msg)
}

// SendOutputChunk sends an output chunk during action execution.
func (c *Client) SendOutputChunk(ctx context.Context, chunk *pm.OutputChunk) error {
	c.mu.RLock()
	stream := c.stream
	c.mu.RUnlock()

	if stream == nil {
		return errors.New("not connected")
	}

	msg := &pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_OutputChunk{
			OutputChunk: chunk,
		},
	}

	return stream.Send(msg)
}

// SendQueryResult sends an OS query result to the server.
func (c *Client) SendQueryResult(ctx context.Context, result *pm.OSQueryResult) error {
	c.mu.RLock()
	stream := c.stream
	c.mu.RUnlock()

	if stream == nil {
		return errors.New("not connected")
	}

	msg := &pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_QueryResult{
			QueryResult: result,
		},
	}

	return stream.Send(msg)
}

// SendSecurityAlert sends a security alert to the server for audit logging.
func (c *Client) SendSecurityAlert(ctx context.Context, alert *pm.SecurityAlert) error {
	c.mu.RLock()
	stream := c.stream
	c.mu.RUnlock()

	if stream == nil {
		return errors.New("not connected")
	}

	msg := &pm.AgentMessage{
		Id: NewULID(),
		Payload: &pm.AgentMessage_SecurityAlert{
			SecurityAlert: alert,
		},
	}

	return stream.Send(msg)
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

// Close closes the stream connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stream == nil {
		return nil
	}

	// Close both request and response sides of the stream
	c.stream.CloseRequest()
	c.stream.CloseResponse()
	c.stream = nil
	return nil
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
