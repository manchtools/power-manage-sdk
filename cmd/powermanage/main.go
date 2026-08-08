// Command powermanage is the open operator client for a Power Manage control
// server.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
)

const (
	requestTimeout = 30 * time.Second
	refreshSkew    = 30 * time.Second
)

type app struct {
	stdin       io.Reader
	stdout      io.Writer
	stderr      io.Writer
	httpClient  *http.Client
	openBrowser func(string) error
	now         func() time.Time
	configPath  string
	sessionPath string
}

func main() {
	root, err := newRootCommand()
	if err != nil {
		fmt.Fprintln(os.Stderr, "powermanage:", err)
		os.Exit(1)
	}
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "powermanage:", err)
		os.Exit(1)
	}
}

func newRootCommand() (*cobra.Command, error) {
	_, configPath, sessionPath, err := configPaths()
	if err != nil {
		return nil, err
	}
	a := &app{
		stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr,
		httpClient: &http.Client{Timeout: requestTimeout}, openBrowser: openBrowser,
		now: time.Now, configPath: configPath, sessionPath: sessionPath,
	}
	root := &cobra.Command{
		Use: "powermanage", Short: "Operate a Power Manage control server",
		SilenceUsage: true, SilenceErrors: true,
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}
	root.SetIn(a.stdin)
	root.SetOut(a.stdout)
	root.SetErr(a.stderr)
	root.AddCommand(
		a.configCommand(), a.bootstrapCommand(), a.loginCommand(), a.authCommand(),
		a.whoamiCommand(), a.logoutCommand(), a.actionCommand(), a.assignmentCommand(),
		a.enrollmentTokenCommand(),
	)
	return root, nil
}

func (a *app) configCommand() *cobra.Command {
	command := &cobra.Command{Use: "config", Short: "Configure the local client"}
	command.AddCommand(&cobra.Command{
		Use: "set-server <url>", Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			serverURL, err := validateServerURL(args[0])
			if err != nil {
				return err
			}
			return writePrivateJSON(a.configPath, configFile{ServerURL: serverURL})
		},
	})
	return command
}

func (a *app) bootstrapCommand() *cobra.Command {
	command := &cobra.Command{Use: "bootstrap", Short: "Bootstrap a fresh deployment"}
	var file string
	var tokenStdin bool
	oidc := &cobra.Command{
		Use: "oidc", Short: "Register the first OIDC provider",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !tokenStdin {
				return errors.New("--token-stdin is required")
			}
			token, err := readBootstrapToken(a.stdin)
			if err != nil {
				return err
			}
			var request pmv1.CreateIdentityProviderRequest
			if err := readProtoJSONFile(file, a.stdin, &request); err != nil {
				return err
			}
			client, _, err := a.publicClient()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), requestTimeout)
			defer cancel()
			req := connect.NewRequest(&request)
			req.Header().Set("Authorization", "PowerManage-Bootstrap "+token)
			response, err := client.CreateIdentityProvider(ctx, req)
			if err != nil {
				return err
			}
			return writeProtoJSON(a.stdout, response.Msg)
		},
	}
	oidc.Flags().StringVar(&file, "file", "", "ProtoJSON request file, or - for stdin")
	oidc.Flags().BoolVar(&tokenStdin, "token-stdin", false, "read the bootstrap token from stdin")
	_ = oidc.MarkFlagRequired("file")
	command.AddCommand(oidc)
	return command
}

func (a *app) loginCommand() *cobra.Command {
	var provider string
	var callbackPort int
	command := &cobra.Command{
		Use: "login", Short: "Sign in through an OIDC provider",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.login(cmd.Context(), provider, callbackPort)
		},
	}
	command.Flags().StringVar(&provider, "provider", "", "identity provider slug")
	command.Flags().IntVar(&callbackPort, "callback-port", 0, "fixed loopback callback port (default: ephemeral)")
	_ = command.MarkFlagRequired("provider")
	return command
}

func (a *app) authCommand() *cobra.Command {
	command := &cobra.Command{Use: "auth", Short: "Expose short-lived local credentials"}
	command.AddCommand(&cobra.Command{
		Use: "token", Short: "Print a Terraform-compatible access token",
		RunE: func(cmd *cobra.Command, _ []string) error {
			session, err := a.currentSession(cmd.Context(), false)
			if err != nil {
				return err
			}
			return json.NewEncoder(a.stdout).Encode(struct {
				ServerURL   string    `json:"server_url"`
				AccessToken string    `json:"access_token"`
				ExpiresAt   time.Time `json:"expires_at"`
			}{session.ServerURL, session.AccessToken, session.ExpiresAt})
		},
	})
	return command
}

func (a *app) whoamiCommand() *cobra.Command {
	return &cobra.Command{
		Use: "whoami", Short: "Show the signed-in user",
		RunE: func(cmd *cobra.Command, _ []string) error {
			response, err := callAuthenticated(cmd.Context(), a, &pmv1.GetCurrentUserRequest{},
				func(ctx context.Context, client powermanagev1connect.ControlServiceClient, req *connect.Request[pmv1.GetCurrentUserRequest]) (*connect.Response[pmv1.GetCurrentUserResponse], error) {
					return client.GetCurrentUser(ctx, req)
				})
			if err != nil {
				return err
			}
			return writeProtoJSON(a.stdout, response.Msg)
		},
	}
}

func (a *app) logoutCommand() *cobra.Command {
	return &cobra.Command{
		Use: "logout", Short: "Revoke and remove the local session",
		RunE: func(cmd *cobra.Command, _ []string) error {
			session, err := readSession(a.sessionPath)
			if err != nil {
				return err
			}
			client := a.client(session.ServerURL)
			ctx, cancel := context.WithTimeout(cmd.Context(), requestTimeout)
			defer cancel()
			if _, err := client.Logout(ctx, connect.NewRequest(&pmv1.LogoutRequest{RefreshToken: session.RefreshToken})); err != nil {
				return err
			}
			if err := os.Remove(a.sessionPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove local session: %w", err)
			}
			return nil
		},
	}
}

func (a *app) actionCommand() *cobra.Command {
	command := &cobra.Command{Use: "action", Short: "Manage actions"}
	command.AddCommand(
		fileRPC(a, "create", func() *pmv1.CreateActionRequest { return &pmv1.CreateActionRequest{} },
			func(ctx context.Context, c powermanagev1connect.ControlServiceClient, r *connect.Request[pmv1.CreateActionRequest]) (*connect.Response[pmv1.CreateActionResponse], error) {
				return c.CreateAction(ctx, r)
			}),
		idRPC(a, "get <id>", func(id string) *pmv1.GetActionRequest { return &pmv1.GetActionRequest{Id: id} },
			func(ctx context.Context, c powermanagev1connect.ControlServiceClient, r *connect.Request[pmv1.GetActionRequest]) (*connect.Response[pmv1.GetActionResponse], error) {
				return c.GetAction(ctx, r)
			}),
		emptyRPC(a, "list", &pmv1.ListActionsRequest{},
			func(ctx context.Context, c powermanagev1connect.ControlServiceClient, r *connect.Request[pmv1.ListActionsRequest]) (*connect.Response[pmv1.ListActionsResponse], error) {
				return c.ListActions(ctx, r)
			}),
		idRPC(a, "delete <id>", func(id string) *pmv1.DeleteActionRequest { return &pmv1.DeleteActionRequest{Id: id} },
			func(ctx context.Context, c powermanagev1connect.ControlServiceClient, r *connect.Request[pmv1.DeleteActionRequest]) (*connect.Response[pmv1.DeleteActionResponse], error) {
				return c.DeleteAction(ctx, r)
			}),
	)
	return command
}

func (a *app) assignmentCommand() *cobra.Command {
	command := &cobra.Command{Use: "assignment", Short: "Manage assignments"}
	command.AddCommand(
		fileRPC(a, "create", func() *pmv1.CreateAssignmentRequest { return &pmv1.CreateAssignmentRequest{} },
			func(ctx context.Context, c powermanagev1connect.ControlServiceClient, r *connect.Request[pmv1.CreateAssignmentRequest]) (*connect.Response[pmv1.CreateAssignmentResponse], error) {
				return c.CreateAssignment(ctx, r)
			}),
		emptyRPC(a, "list", &pmv1.ListAssignmentsRequest{},
			func(ctx context.Context, c powermanagev1connect.ControlServiceClient, r *connect.Request[pmv1.ListAssignmentsRequest]) (*connect.Response[pmv1.ListAssignmentsResponse], error) {
				return c.ListAssignments(ctx, r)
			}),
		idRPC(a, "delete <id>", func(id string) *pmv1.DeleteAssignmentRequest { return &pmv1.DeleteAssignmentRequest{Id: id} },
			func(ctx context.Context, c powermanagev1connect.ControlServiceClient, r *connect.Request[pmv1.DeleteAssignmentRequest]) (*connect.Response[pmv1.DeleteAssignmentResponse], error) {
				return c.DeleteAssignment(ctx, r)
			}),
	)
	return command
}

func (a *app) enrollmentTokenCommand() *cobra.Command {
	command := &cobra.Command{Use: "enrollment-token", Short: "Manage device enrollment tokens"}
	command.AddCommand(
		fileRPC(a, "create", func() *pmv1.CreateTokenRequest { return &pmv1.CreateTokenRequest{} },
			func(ctx context.Context, c powermanagev1connect.ControlServiceClient, r *connect.Request[pmv1.CreateTokenRequest]) (*connect.Response[pmv1.CreateTokenResponse], error) {
				return c.CreateToken(ctx, r)
			}),
		idRPC(a, "get <id>", func(id string) *pmv1.GetTokenRequest { return &pmv1.GetTokenRequest{Id: id} },
			func(ctx context.Context, c powermanagev1connect.ControlServiceClient, r *connect.Request[pmv1.GetTokenRequest]) (*connect.Response[pmv1.GetTokenResponse], error) {
				return c.GetToken(ctx, r)
			}),
		emptyRPC(a, "list", &pmv1.ListTokensRequest{},
			func(ctx context.Context, c powermanagev1connect.ControlServiceClient, r *connect.Request[pmv1.ListTokensRequest]) (*connect.Response[pmv1.ListTokensResponse], error) {
				return c.ListTokens(ctx, r)
			}),
		setTokenDisabledRPC(a, "enable <id>", false),
		setTokenDisabledRPC(a, "disable <id>", true),
		idRPC(a, "delete <id>", func(id string) *pmv1.DeleteTokenRequest { return &pmv1.DeleteTokenRequest{Id: id} },
			func(ctx context.Context, c powermanagev1connect.ControlServiceClient, r *connect.Request[pmv1.DeleteTokenRequest]) (*connect.Response[pmv1.DeleteTokenResponse], error) {
				return c.DeleteToken(ctx, r)
			}),
	)
	return command
}

func (a *app) publicClient() (powermanagev1connect.ControlServiceClient, string, error) {
	var config configFile
	if err := readPrivateJSON(a.configPath, &config); err != nil {
		return nil, "", fmt.Errorf("read local config (run 'powermanage config set-server <url>'): %w", err)
	}
	serverURL, err := validateServerURL(config.ServerURL)
	if err != nil {
		return nil, "", fmt.Errorf("invalid stored server URL: %w", err)
	}
	return a.client(serverURL), serverURL, nil
}

func (a *app) client(serverURL string) powermanagev1connect.ControlServiceClient {
	return powermanagev1connect.NewControlServiceClient(a.httpClient, serverURL,
		connect.WithSendMaxBytes(maxProtoJSONBytes), connect.WithReadMaxBytes(maxProtoJSONBytes))
}

func readBootstrapToken(r io.Reader) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 4097))
	if err != nil {
		return "", fmt.Errorf("read bootstrap token: %w", err)
	}
	if len(raw) > 4096 {
		return "", errors.New("bootstrap token is too large")
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("bootstrap token must be one non-empty value")
	}
	return token, nil
}

func readProtoJSONFile(path string, stdin io.Reader, message proto.Message) error {
	if path == "" {
		return errors.New("--file is required")
	}
	if path == "-" {
		return readProtoJSON(stdin, message)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open ProtoJSON file: %w", err)
	}
	defer file.Close()
	return readProtoJSON(file, message)
}

func callAuthenticated[I, O any](ctx context.Context, a *app, message *I, call func(context.Context, powermanagev1connect.ControlServiceClient, *connect.Request[I]) (*connect.Response[O], error)) (*connect.Response[O], error) {
	session, err := a.currentSession(ctx, false)
	if err != nil {
		return nil, err
	}
	do := func(session sessionFile) (*connect.Response[O], error) {
		request := connect.NewRequest(message)
		request.Header().Set("Authorization", "Bearer "+session.AccessToken)
		requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		defer cancel()
		return call(requestCtx, a.client(session.ServerURL), request)
	}
	response, err := do(session)
	if err == nil || !isExpiredTokenError(err) {
		return response, err
	}
	session, err = a.currentSession(ctx, true)
	if err != nil {
		return nil, err
	}
	return do(session)
}

func isExpiredTokenError(err error) bool {
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) || connectErr.Code() != connect.CodeUnauthenticated {
		return false
	}
	for _, detail := range connectErr.Details() {
		value, detailErr := detail.Value()
		if detailErr != nil {
			// A malformed optional detail cannot turn a generic
			// unauthenticated response into a refresh instruction.
			continue
		}
		if typed, ok := value.(*pmv1.ErrorDetail); ok && typed.Code == "token_expired" {
			return true
		}
	}
	return false
}

func (a *app) currentSession(ctx context.Context, forceRefresh bool) (sessionFile, error) {
	if !forceRefresh {
		session, err := readSession(a.sessionPath)
		if err != nil {
			return sessionFile{}, fmt.Errorf("read local session (run 'powermanage login'): %w", err)
		}
		if session.ExpiresAt.After(a.now().Add(refreshSkew)) {
			return session, nil
		}
	}
	return a.refreshSession(ctx, forceRefresh)
}

func (a *app) refreshSession(ctx context.Context, force bool) (sessionFile, error) {
	lockPath := a.sessionPath + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return sessionFile{}, fmt.Errorf("create config directory: %w", err)
	}
	fd, err := unix.Open(lockPath, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return sessionFile{}, fmt.Errorf("open session lock: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		return sessionFile{}, fmt.Errorf("lock session: %w", err)
	}
	defer func() {
		// Closing the descriptor releases the lock even if this best-effort
		// explicit unlock reports an error.
		_ = unix.Flock(fd, unix.LOCK_UN)
	}()
	session, err := readSession(a.sessionPath)
	if err != nil {
		return sessionFile{}, err
	}
	if !force && session.ExpiresAt.After(a.now().Add(refreshSkew)) {
		return session, nil
	}
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	response, err := a.client(session.ServerURL).RefreshToken(requestCtx,
		connect.NewRequest(&pmv1.RefreshTokenRequest{RefreshToken: session.RefreshToken}))
	if err != nil {
		return sessionFile{}, err
	}
	if response.Msg.AccessToken == "" || response.Msg.RefreshToken == "" || response.Msg.ExpiresAt == nil {
		return sessionFile{}, errors.New("control returned an incomplete refreshed session")
	}
	session.AccessToken = response.Msg.AccessToken
	session.RefreshToken = response.Msg.RefreshToken
	session.ExpiresAt = response.Msg.ExpiresAt.AsTime()
	if err := writeSession(a.sessionPath, session); err != nil {
		return sessionFile{}, err
	}
	return session, nil
}

func fileRPC[I, O any](a *app, use string, newRequest func() *I, call func(context.Context, powermanagev1connect.ControlServiceClient, *connect.Request[I]) (*connect.Response[O], error)) *cobra.Command {
	var path string
	command := &cobra.Command{
		Use: use,
		RunE: func(cmd *cobra.Command, _ []string) error {
			request := newRequest()
			message, ok := any(request).(proto.Message)
			if !ok {
				return errors.New("request is not a protobuf message")
			}
			if err := readProtoJSONFile(path, a.stdin, message); err != nil {
				return err
			}
			response, err := callAuthenticated(cmd.Context(), a, request, call)
			if err != nil {
				return err
			}
			return writeRPCResponse(a.stdout, response.Msg)
		},
	}
	command.Flags().StringVar(&path, "file", "", "ProtoJSON request file, or - for stdin")
	_ = command.MarkFlagRequired("file")
	return command
}

func idRPC[I, O any](a *app, use string, newRequest func(string) *I, call func(context.Context, powermanagev1connect.ControlServiceClient, *connect.Request[I]) (*connect.Response[O], error)) *cobra.Command {
	return &cobra.Command{
		Use: use, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			response, err := callAuthenticated(cmd.Context(), a, newRequest(args[0]), call)
			if err != nil {
				return err
			}
			return writeRPCResponse(a.stdout, response.Msg)
		},
	}
}

func emptyRPC[I, O any](a *app, use string, request *I, call func(context.Context, powermanagev1connect.ControlServiceClient, *connect.Request[I]) (*connect.Response[O], error)) *cobra.Command {
	return &cobra.Command{
		Use: use, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			response, err := callAuthenticated(cmd.Context(), a, request, call)
			if err != nil {
				return err
			}
			return writeRPCResponse(a.stdout, response.Msg)
		},
	}
}

func writeRPCResponse[T any](w io.Writer, response *T) error {
	message, ok := any(response).(proto.Message)
	if !ok {
		return errors.New("response is not a protobuf message")
	}
	return writeProtoJSON(w, message)
}

func setTokenDisabledRPC(a *app, use string, disabled bool) *cobra.Command {
	return idRPC(a, use,
		func(id string) *pmv1.SetTokenDisabledRequest {
			return &pmv1.SetTokenDisabledRequest{Id: id, Disabled: disabled}
		},
		func(ctx context.Context, c powermanagev1connect.ControlServiceClient, r *connect.Request[pmv1.SetTokenDisabledRequest]) (*connect.Response[pmv1.UpdateTokenResponse], error) {
			return c.SetTokenDisabled(ctx, r)
		})
}

func (a *app) login(ctx context.Context, provider string, callbackPort int) error {
	if _, err := parsePort(fmt.Sprint(callbackPort)); err != nil {
		return err
	}
	listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", callbackPort))
	if err != nil {
		return fmt.Errorf("bind loopback callback: %w", err)
	}
	defer listener.Close()
	redirectURL := "http://" + listener.Addr().String() + "/callback"
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return fmt.Errorf("generate PKCE verifier: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	client, serverURL, err := a.publicClient()
	if err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	begin, err := client.BeginCLILogin(requestCtx, connect.NewRequest(&pmv1.BeginCLILoginRequest{
		Slug: provider, RedirectUrl: redirectURL, CodeChallenge: challenge,
	}))
	cancel()
	if err != nil {
		return err
	}
	if begin.Msg.ExpiresAt == nil || begin.Msg.State == "" || begin.Msg.LoginUrl == "" || begin.Msg.TokenUrl == "" || begin.Msg.ClientId == "" {
		return errors.New("control returned an incomplete CLI login")
	}
	callback := make(chan callbackResult, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		result := callbackResult{code: r.URL.Query().Get("code"), state: r.URL.Query().Get("state"), oauthError: r.URL.Query().Get("error")}
		select {
		case callback <- result:
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "Power Manage sign-in received. You may close this window.\n")
		default:
			http.Error(w, "Sign-in callback already received.", http.StatusConflict)
		}
	})
	callbackServer := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	serveDone := make(chan error, 1)
	go func() { serveDone <- callbackServer.Serve(listener) }()
	if err := a.openBrowser(begin.Msg.LoginUrl); err != nil {
		fmt.Fprintln(a.stderr, "Open this URL to sign in:", begin.Msg.LoginUrl)
	}
	var received callbackResult
	wait := time.Until(begin.Msg.ExpiresAt.AsTime())
	if wait <= 0 {
		wait = time.Millisecond
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errors.New("OIDC login timed out")
	case received = <-callback:
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
	_ = callbackServer.Shutdown(shutdownCtx)
	shutdownCancel()
	select {
	case serveErr := <-serveDone:
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return fmt.Errorf("serve loopback callback: %w", serveErr)
		}
	default:
	}
	if received.oauthError != "" || received.code == "" || received.state != begin.Msg.State {
		return errors.New("OIDC callback was rejected")
	}
	exchangeCtx, exchangeCancel := context.WithTimeout(ctx, requestTimeout)
	idToken, err := exchangeOIDCCode(exchangeCtx, a.httpClient, begin.Msg.TokenUrl, begin.Msg.ClientId,
		received.code, redirectURL, verifier)
	exchangeCancel()
	if err != nil {
		return err
	}
	controlCtx, controlCancel := context.WithTimeout(ctx, requestTimeout)
	session, err := client.ExchangeCLISession(controlCtx, connect.NewRequest(&pmv1.ExchangeCLISessionRequest{
		Slug: provider, State: begin.Msg.State, IdToken: idToken,
	}))
	controlCancel()
	if err != nil {
		return err
	}
	if session.Msg.AccessToken == "" || session.Msg.RefreshToken == "" || session.Msg.ExpiresAt == nil {
		return errors.New("control returned an incomplete session")
	}
	return writeSession(a.sessionPath, sessionFile{
		ServerURL: serverURL, AccessToken: session.Msg.AccessToken,
		RefreshToken: session.Msg.RefreshToken, ExpiresAt: session.Msg.ExpiresAt.AsTime(),
	})
}

type callbackResult struct {
	code       string
	state      string
	oauthError string
}

func openBrowser(rawURL string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", rawURL)
	case "linux":
		command = exec.Command("xdg-open", rawURL)
	default:
		return fmt.Errorf("automatic browser opening is unsupported on %s", runtime.GOOS)
	}
	if err := command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
}
