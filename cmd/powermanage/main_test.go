package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
)

func TestValidateServerURL(t *testing.T) {
	for _, accepted := range []string{
		"https://control.example",
		"https://control.example/power-manage",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
	} {
		got, err := validateServerURL(accepted)
		require.NoError(t, err, accepted)
		assert.Equal(t, accepted, got)
	}
	for _, rejected := range []string{
		"http://control.example",
		"http://localhost:8080",
		"https://user:pass@control.example",
		"https://control.example?token=secret",
		"https://control.example/#fragment",
		"file:///tmp/control.sock",
	} {
		_, err := validateServerURL(rejected)
		assert.Error(t, err, rejected)
	}
}

func TestRootCommandDoesNotAdvertiseOutOfScopeCompletion(t *testing.T) {
	root, err := newRootCommand()
	require.NoError(t, err)
	root.InitDefaultCompletionCmd()
	for _, command := range root.Commands() {
		assert.NotEqual(t, "completion", command.Name())
	}
}

func TestReadProtoJSONRejectsUnknownAndOversizedInput(t *testing.T) {
	for name, input := range map[string]string{
		"unknown":   `{"name":"token","unknown":true}`,
		"malformed": `{"name":`,
		"oversized": strings.Repeat(" ", maxProtoJSONBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			var request pmv1.CreateTokenRequest
			assert.Error(t, readProtoJSON(strings.NewReader(input), &request))
		})
	}
}

func TestExchangeOIDCCodeKeepsTheVerifierAndCodeOutOfControl(t *testing.T) {
	var received url.Values
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		received = r.Form
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"id_token":"signed.assertion","access_token":"idp-access","refresh_token":"idp-refresh"}`))
		require.NoError(t, err)
	}))
	t.Cleanup(tokenServer.Close)

	idToken, err := exchangeOIDCCode(t.Context(), tokenServer.Client(), tokenServer.URL,
		"powermanage-cli", "authorization-code", "http://127.0.0.1:45123/callback", "local-verifier")
	require.NoError(t, err)
	assert.Equal(t, "signed.assertion", idToken)
	assert.Equal(t, "authorization_code", received.Get("grant_type"))
	assert.Equal(t, "authorization-code", received.Get("code"))
	assert.Equal(t, "local-verifier", received.Get("code_verifier"))
	assert.Empty(t, received.Get("client_secret"))
}

func TestWriteSessionUsesPrivateAtomicStorage(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "powermanage")
	path := filepath.Join(directory, "session.json")
	want := sessionFile{
		ServerURL: "https://control.example", AccessToken: "access", RefreshToken: "refresh",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, writeSession(path, want))

	directoryInfo, err := os.Stat(directory)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), directoryInfo.Mode().Perm())
	fileInfo, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fileInfo.Mode().Perm())
	got, err := readSession(path)
	require.NoError(t, err)
	assert.Equal(t, want.ServerURL, got.ServerURL)
	assert.Equal(t, want.RefreshToken, got.RefreshToken)

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.True(t, bytes.Contains(raw, []byte("refresh")), "the local session intentionally retains the refresh token")
}

func TestReadSessionRejectsSymlinksAndBroadPermissions(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "powermanage")
	realPath := filepath.Join(directory, "real.json")
	require.NoError(t, writeSession(realPath, sessionFile{
		ServerURL: "https://control.example", AccessToken: "access", RefreshToken: "refresh", ExpiresAt: time.Now().Add(time.Hour),
	}))
	symlinkPath := filepath.Join(directory, "session.json")
	require.NoError(t, os.Symlink(realPath, symlinkPath))
	_, err := readSession(symlinkPath)
	assert.Error(t, err)

	require.NoError(t, os.Remove(symlinkPath))
	require.NoError(t, os.Rename(realPath, symlinkPath))
	require.NoError(t, os.Chmod(symlinkPath, 0o640))
	_, err = readSession(symlinkPath)
	assert.Error(t, err)
}

func TestConcurrentRefreshSpendsOneRefreshToken(t *testing.T) {
	var mu sync.Mutex
	refreshCalls := 0
	mux := http.NewServeMux()
	mux.Handle(powermanagev1connect.ControlServiceRefreshTokenProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceRefreshTokenProcedure,
			func(_ context.Context, request *connect.Request[pmv1.RefreshTokenRequest]) (*connect.Response[pmv1.RefreshTokenResponse], error) {
				mu.Lock()
				refreshCalls++
				mu.Unlock()
				assert.Equal(t, "old-refresh", request.Msg.RefreshToken)
				return connect.NewResponse(&pmv1.RefreshTokenResponse{
					AccessToken: "new-access", RefreshToken: "new-refresh",
					ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
				}), nil
			}))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	directory := filepath.Join(t.TempDir(), "powermanage")
	a := &app{httpClient: server.Client(), now: time.Now, sessionPath: filepath.Join(directory, "session.json")}
	require.NoError(t, writeSession(a.sessionPath, sessionFile{
		ServerURL: server.URL, AccessToken: "old-access", RefreshToken: "old-refresh", ExpiresAt: time.Now().Add(-time.Minute),
	}))

	results := make(chan sessionFile, 2)
	errorsCh := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			session, err := a.currentSession(t.Context(), false)
			results <- session
			errorsCh <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errorsCh)
	for err := range errorsCh {
		require.NoError(t, err)
	}
	for session := range results {
		assert.Equal(t, "new-refresh", session.RefreshToken)
	}
	mu.Lock()
	assert.Equal(t, 1, refreshCalls)
	mu.Unlock()
}

func TestExchangeOIDCCodeRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxOIDCTokenResponseBytes+1))
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, err := exchangeOIDCCode(ctx, server.Client(), server.URL, "client", "code", "http://127.0.0.1:1/callback", "verifier")
	assert.Error(t, err)
}

func TestActionCreateMapsProtoJSONDirectlyToTheGeneratedRPC(t *testing.T) {
	var calls int
	mux := http.NewServeMux()
	mux.Handle(powermanagev1connect.ControlServiceCreateActionProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceCreateActionProcedure,
			func(_ context.Context, request *connect.Request[pmv1.CreateActionRequest]) (*connect.Response[pmv1.CreateActionResponse], error) {
				calls++
				assert.Equal(t, "Bearer access", request.Header().Get("Authorization"))
				return connect.NewResponse(&pmv1.CreateActionResponse{Action: &pmv1.ManagedAction{Name: request.Msg.Name}}), nil
			}))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	directory := filepath.Join(t.TempDir(), "powermanage")
	a := &app{
		stdin: strings.NewReader(""), stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{},
		httpClient: server.Client(), now: time.Now,
		configPath: filepath.Join(directory, "config.json"), sessionPath: filepath.Join(directory, "session.json"),
	}
	require.NoError(t, writeSession(a.sessionPath, sessionFile{
		ServerURL: server.URL, AccessToken: "access", RefreshToken: "refresh", ExpiresAt: time.Now().Add(time.Hour),
	}))
	requestPath := filepath.Join(directory, "action.json")
	require.NoError(t, os.WriteFile(requestPath, []byte(`{"name":"package update","type":"ACTION_TYPE_PACKAGE"}`), 0o600))
	command := a.actionCommand()
	command.SetArgs([]string{"create", "--file", requestPath})
	require.NoError(t, command.ExecuteContext(t.Context()))
	assert.Equal(t, 1, calls)
	var output pmv1.CreateActionResponse
	require.NoError(t, protojson.Unmarshal(a.stdout.(*bytes.Buffer).Bytes(), &output))
	assert.Equal(t, "package update", output.Action.Name)

	require.NoError(t, os.WriteFile(requestPath, []byte(`{"name":"bad","unknown":true}`), 0o600))
	command = a.actionCommand()
	command.SetArgs([]string{"create", "--file", requestPath})
	assert.Error(t, command.ExecuteContext(t.Context()))
	assert.Equal(t, 1, calls, "invalid ProtoJSON must fail before any RPC")
}

func TestLoginKeepsTheAuthorizationCodeAndVerifierAtTheIdentityProvider(t *testing.T) {
	var tokenForm url.Values
	var tokenCalls int
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCalls++
		require.NoError(t, r.ParseForm())
		tokenForm = r.Form
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id_token":"signed.assertion","access_token":"idp-access","refresh_token":"idp-refresh"}`)
	}))
	t.Cleanup(tokenServer.Close)

	const loginState = "one-use-state"
	mux := http.NewServeMux()
	mux.Handle(powermanagev1connect.ControlServiceBeginCLILoginProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceBeginCLILoginProcedure,
			func(_ context.Context, request *connect.Request[pmv1.BeginCLILoginRequest]) (*connect.Response[pmv1.BeginCLILoginResponse], error) {
				loginURL := "https://idp.example/authorize?" + url.Values{
					"redirect_uri": {request.Msg.RedirectUrl}, "state": {loginState},
				}.Encode()
				return connect.NewResponse(&pmv1.BeginCLILoginResponse{
					LoginUrl: loginURL, State: loginState, TokenUrl: tokenServer.URL,
					ClientId: "powermanage-cli", ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
				}), nil
			}))
	mux.Handle(powermanagev1connect.ControlServiceExchangeCLISessionProcedure,
		connect.NewUnaryHandler(powermanagev1connect.ControlServiceExchangeCLISessionProcedure,
			func(_ context.Context, request *connect.Request[pmv1.ExchangeCLISessionRequest]) (*connect.Response[pmv1.ExchangeCLISessionResponse], error) {
				assert.Equal(t, "signed.assertion", request.Msg.IdToken)
				assert.NotContains(t, request.Msg.String(), "authorization-code")
				assert.NotContains(t, request.Msg.String(), tokenForm.Get("code_verifier"))
				return connect.NewResponse(&pmv1.ExchangeCLISessionResponse{
					AccessToken: "pm-access", RefreshToken: "pm-refresh",
					ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
				}), nil
			}))
	control := httptest.NewServer(mux)
	t.Cleanup(control.Close)

	directory := filepath.Join(t.TempDir(), "powermanage")
	a := &app{
		stdin: strings.NewReader(""), stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{},
		httpClient: control.Client(), now: time.Now,
		configPath: filepath.Join(directory, "config.json"), sessionPath: filepath.Join(directory, "session.json"),
	}
	require.NoError(t, writePrivateJSON(a.configPath, configFile{ServerURL: control.URL}))
	a.openBrowser = func(loginURL string) error {
		parsed, err := url.Parse(loginURL)
		require.NoError(t, err)
		callback := parsed.Query().Get("redirect_uri") + "?code=authorization-code&state=" + loginState
		response, err := http.Get(callback)
		if err == nil {
			_ = response.Body.Close()
		}
		return err
	}
	require.NoError(t, a.login(t.Context(), "corp", 0))
	assert.Equal(t, "authorization-code", tokenForm.Get("code"))
	assert.NotEmpty(t, tokenForm.Get("code_verifier"))
	assert.Empty(t, tokenForm.Get("client_secret"))
	assert.Equal(t, 1, tokenCalls)
	session, err := readSession(a.sessionPath)
	require.NoError(t, err)
	assert.Equal(t, "pm-refresh", session.RefreshToken)

	wrongDirectory := filepath.Join(t.TempDir(), "powermanage")
	wrongStateApp := &app{
		stdin: strings.NewReader(""), stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{},
		httpClient: control.Client(), now: time.Now,
		configPath: filepath.Join(wrongDirectory, "config.json"), sessionPath: filepath.Join(wrongDirectory, "session.json"),
	}
	require.NoError(t, writePrivateJSON(wrongStateApp.configPath, configFile{ServerURL: control.URL}))
	wrongStateApp.openBrowser = func(loginURL string) error {
		parsed, err := url.Parse(loginURL)
		require.NoError(t, err)
		callback := parsed.Query().Get("redirect_uri") + "?code=stolen-code&state=wrong-state"
		response, err := http.Get(callback)
		if err == nil {
			_ = response.Body.Close()
		}
		return err
	}
	assert.Error(t, wrongStateApp.login(t.Context(), "corp", 0))
	assert.Equal(t, 1, tokenCalls, "wrong callback state must stop before the IdP token endpoint")
}
