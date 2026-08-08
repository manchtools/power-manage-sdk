package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	maxProtoJSONBytes         = 8 << 20
	maxOIDCTokenResponseBytes = 1 << 20
	maxCredentialFileBytes    = 64 << 10
)

type configFile struct {
	ServerURL string `json:"server_url"`
}

type sessionFile struct {
	ServerURL    string    `json:"server_url"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func validateServerURL(raw string) (string, error) {
	if raw != strings.TrimSpace(raw) || raw == "" {
		return "", errors.New("server URL is empty or contains surrounding whitespace")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("server URL must be an HTTP(S) origin without credentials, query, or fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return "", errors.New("cleartext HTTP is allowed only for a literal loopback address")
		}
	default:
		return "", errors.New("server URL must use HTTPS")
	}
	return raw, nil
}

func readProtoJSON(r io.Reader, message proto.Message) error {
	if r == nil || message == nil {
		return errors.New("ProtoJSON input and message are required")
	}
	raw, err := io.ReadAll(io.LimitReader(r, maxProtoJSONBytes+1))
	if err != nil {
		return fmt.Errorf("read ProtoJSON: %w", err)
	}
	if len(raw) > maxProtoJSONBytes {
		return fmt.Errorf("ProtoJSON input exceeds %d bytes", maxProtoJSONBytes)
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(raw, message); err != nil {
		return fmt.Errorf("decode ProtoJSON: %w", err)
	}
	return nil
}

func writeProtoJSON(w io.Writer, message proto.Message) error {
	if w == nil || message == nil {
		return errors.New("ProtoJSON output and message are required")
	}
	raw, err := (protojson.MarshalOptions{Multiline: true, Indent: "  "}).Marshal(message)
	if err != nil {
		return fmt.Errorf("encode ProtoJSON: %w", err)
	}
	if _, err := w.Write(append(raw, '\n')); err != nil {
		return fmt.Errorf("write ProtoJSON: %w", err)
	}
	return nil
}

func configPaths() (directory, configPath, sessionPath string, err error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", "", "", fmt.Errorf("find user config directory: %w", err)
	}
	directory = filepath.Join(base, "powermanage")
	return directory, filepath.Join(directory, "config.json"), filepath.Join(directory, "session.json"), nil
}

func writeSession(path string, session sessionFile) error {
	if _, err := validateServerURL(session.ServerURL); err != nil {
		return fmt.Errorf("invalid session server: %w", err)
	}
	if session.AccessToken == "" || session.RefreshToken == "" || session.ExpiresAt.IsZero() {
		return errors.New("session is incomplete")
	}
	return writePrivateJSON(path, session)
}

func readSession(path string) (sessionFile, error) {
	var session sessionFile
	if err := readPrivateJSON(path, &session); err != nil {
		return session, err
	}
	if _, err := validateServerURL(session.ServerURL); err != nil {
		return sessionFile{}, fmt.Errorf("invalid stored session: %w", err)
	}
	if session.AccessToken == "" || session.RefreshToken == "" || session.ExpiresAt.IsZero() {
		return sessionFile{}, errors.New("stored session is incomplete")
	}
	return session, nil
}

func openPrivateDirectory(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, fmt.Errorf("open config directory: %w", err)
	}
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		return -1, errors.Join(fmt.Errorf("inspect config directory: %w", err), unix.Close(fd))
	}
	if info.Mode&unix.S_IFMT != unix.S_IFDIR || info.Mode&0o077 != 0 || info.Uid != uint32(unix.Geteuid()) {
		return -1, errors.Join(errors.New("config directory must be private, owned by the current user, and not a symlink"), unix.Close(fd))
	}
	return fd, nil
}

func createTemporaryCredential(dirFD int) (*os.File, string, error) {
	for range 100 {
		var suffix [16]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, "", fmt.Errorf("name temporary credential file: %w", err)
		}
		name := ".powermanage-" + hex.EncodeToString(suffix[:])
		fd, err := unix.Openat(dirFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("create credential file: %w", err)
		}
		file := os.NewFile(uintptr(fd), name)
		if file == nil {
			return nil, "", errors.Join(errors.New("create credential file"), unix.Close(fd), unix.Unlinkat(dirFD, name, 0))
		}
		return file, name, nil
	}
	return nil, "", errors.New("create unique credential file")
}

func writePrivateJSON(path string, value any) (resultErr error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	dirFD, err := openPrivateDirectory(directory)
	if err != nil {
		return err
	}
	defer func() {
		if err := unix.Close(dirFD); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close config directory: %w", err))
		}
	}()
	name := filepath.Base(path)
	if name == "." || name == ".." || name == string(filepath.Separator) {
		return errors.New("credential file path is invalid")
	}
	var existing unix.Stat_t
	if err := unix.Fstatat(dirFD, name, &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if existing.Mode&unix.S_IFMT != unix.S_IFREG || existing.Mode&0o077 != 0 || existing.Uid != uint32(unix.Geteuid()) {
			return errors.New("credential file must be a private regular file owned by the current user")
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("inspect credential file: %w", err)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode credential file: %w", err)
	}
	temporary, temporaryName, err := createTemporaryCredential(dirFD)
	if err != nil {
		return err
	}
	temporaryClosed := false
	renamed := false
	defer func() {
		if !temporaryClosed {
			if err := temporary.Close(); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("close credential file: %w", err))
			}
		}
		if !renamed {
			if err := unix.Unlinkat(dirFD, temporaryName, 0); err != nil && !errors.Is(err, unix.ENOENT) {
				resultErr = errors.Join(resultErr, fmt.Errorf("remove temporary credential file: %w", err))
			}
		}
	}()
	if _, err := temporary.Write(append(raw, '\n')); err != nil {
		return fmt.Errorf("write credential file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync credential file: %w", err)
	}
	closeErr := temporary.Close()
	temporaryClosed = true
	if closeErr != nil {
		return fmt.Errorf("close credential file: %w", closeErr)
	}
	if err := unix.Renameat(dirFD, temporaryName, dirFD, name); err != nil {
		return fmt.Errorf("replace credential file: %w", err)
	}
	renamed = true
	if err := unix.Fsync(dirFD); err != nil {
		return fmt.Errorf("sync config directory: %w", err)
	}
	return nil
}

func readPrivateJSON(path string, value any) (resultErr error) {
	dirFD, err := openPrivateDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() {
		if err := unix.Close(dirFD); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close config directory: %w", err))
		}
	}()
	name := filepath.Base(path)
	if name == "." || name == ".." || name == string(filepath.Separator) {
		return errors.New("credential file path is invalid")
	}
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open credential file: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		return errors.Join(errors.New("open credential file"), unix.Close(fd))
	}
	defer func() {
		if err := file.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close credential file: %w", err))
		}
	}()
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		return fmt.Errorf("inspect credential file: %w", err)
	}
	if info.Mode&unix.S_IFMT != unix.S_IFREG || info.Mode&0o077 != 0 || info.Uid != uint32(unix.Geteuid()) {
		return errors.New("credential file must be a private regular file owned by the current user")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxCredentialFileBytes+1))
	if err != nil {
		return fmt.Errorf("read credential file: %w", err)
	}
	if len(raw) > maxCredentialFileBytes {
		return errors.New("credential file is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("decode credential file: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("credential file contains multiple JSON values")
		}
		return fmt.Errorf("decode trailing credential data: %w", err)
	}
	return nil
}

func exchangeOIDCCode(ctx context.Context, client *http.Client, tokenURL, clientID, code, redirectURL, verifier string) (_ string, resultErr error) {
	if client == nil {
		return "", errors.New("OIDC HTTP client is required")
	}
	if _, err := validateServerURL(tokenURL); err != nil {
		return "", fmt.Errorf("unsafe OIDC token endpoint: %w", err)
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURL},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build OIDC token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("identity provider exchange failed: %w", err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close identity provider response: %w", err))
		}
	}()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("identity provider exchange failed with HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxOIDCTokenResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("read identity provider response: %w", err)
	}
	if len(raw) > maxOIDCTokenResponseBytes {
		return "", errors.New("identity provider response is too large")
	}
	var token struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(raw, &token); err != nil {
		return "", errors.New("identity provider returned no valid ID token")
	}
	if token.Error != "" {
		return "", errors.New("identity provider rejected the exchange")
	}
	if token.IDToken == "" {
		return "", errors.New("identity provider returned no valid ID token")
	}
	return token.IDToken, nil
}

func parsePort(raw string) (int, error) {
	port, err := strconv.Atoi(raw)
	if err != nil || port < 0 || port > 65535 {
		return 0, errors.New("callback port must be between 0 and 65535")
	}
	return port, nil
}
