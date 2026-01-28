// Package sdk provides a client library for communicating with the power-manage server.
package sdk

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/oklog/ulid/v2"

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

// Register registers a new agent with the server.
func (c *Client) Register(ctx context.Context, token, hostname, agentVersion string) (*pm.RegisterResponse, error) {
	req := connect.NewRequest(&pm.RegisterRequest{
		Token:        token,
		Hostname:     hostname,
		AgentVersion: agentVersion,
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

	err := c.stream.CloseRequest()
	c.stream = nil
	return err
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

	// Process incoming messages
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		msg, err := c.Receive(ctx)
		if err != nil {
			return fmt.Errorf("receive: %w", err)
		}

		switch p := msg.Payload.(type) {
		case *pm.ServerMessage_Welcome:
			if err := handler.OnWelcome(ctx, p.Welcome); err != nil {
				return fmt.Errorf("handle welcome: %w", err)
			}

		case *pm.ServerMessage_Action:
			result, err := handler.OnAction(ctx, p.Action.Action)
			if err != nil {
				return fmt.Errorf("handle action: %w", err)
			}
			if result != nil {
				if err := c.SendActionResult(ctx, result); err != nil {
					return fmt.Errorf("send action result: %w", err)
				}
			}

		case *pm.ServerMessage_Query:
			result, err := handler.OnQuery(ctx, p.Query)
			if err != nil {
				return fmt.Errorf("handle query: %w", err)
			}
			if result != nil {
				if err := c.SendQueryResult(ctx, result); err != nil {
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
