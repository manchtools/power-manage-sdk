// Package osquery integrates the osquery binary for system queries through an
// injected exec.Runner.
//
// Build a Client with a Runner and call its methods; every query is escalated
// through the Runner. The convenience table path refuses a curated deny-list of
// credential-bearing tables before running anything; the signed RawSql escape
// hatch is the operator's explicit path and is intentionally not gated.
//
//	r, _ := exec.NewRunner(exec.Sudo)
//	c, err := osquery.NewClient(r) // ErrNotInstalled if osqueryi is absent
package osquery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	osexec "os/exec"
	"regexp"
	"strings"
	"time"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// validTableName matches only safe osquery table names (alphanumeric + underscore).
var validTableName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// sensitiveTables are osquery tables that can expose credential material or other
// high-value secrets — password-hash metadata (shadow), secrets in process
// environments (process_envs), scheduled commands (crontab), shell history
// (shell_history), and sudoers policy (sudoers). They all pass validTableName, so
// the shape-only check is not enough: the convenience table path refuses them so a
// compromised control server cannot exfiltrate them through the agent's
// privileged osquery. The signed RawSql escape hatch is intentionally NOT gated
// here — it is the operator's explicit, CA-signed path.
var sensitiveTables = map[string]bool{
	"shadow":        true,
	"process_envs":  true,
	"crontab":       true,
	"shell_history": true,
	"sudoers":       true,
}

// isSensitiveTable reports whether name is on the curated deny-list. Comparison is
// case- and whitespace-insensitive so trivial variants cannot slip past.
func isSensitiveTable(name string) bool {
	return sensitiveTables[strings.ToLower(strings.TrimSpace(name))]
}

var (
	// ErrNotInstalled is returned when osquery is not installed on the system.
	ErrNotInstalled = errors.New("osquery is not installed")

	// ErrQueryFailed is returned when an osquery query fails.
	ErrQueryFailed = errors.New("osquery query failed")

	// Common osquery binary paths to check.
	osqueryPaths = []string{
		"/usr/bin/osqueryi",
		"/usr/local/bin/osqueryi",
		"/opt/osquery/bin/osqueryi",
	}

	// Default query timeout.
	defaultTimeout = 30 * time.Second
)

// Client wraps osquery binary execution over an injected Runner.
type Client struct {
	binaryPath string
	r          exec.Runner
}

// NewClient creates an osquery client driven by runner. Returns ErrNotInstalled
// when the osqueryi binary is not found, and an error when runner is nil.
func NewClient(runner exec.Runner) (*Client, error) {
	if runner == nil {
		return nil, errors.New("osquery: runner is required")
	}
	path := findOsqueryBinary()
	if path == "" {
		return nil, ErrNotInstalled
	}
	return &Client{binaryPath: path, r: runner}, nil
}

// IsInstalled checks if osquery is installed on the system.
func IsInstalled() bool {
	return findOsqueryBinary() != ""
}

// lookPath is the resolution function used by findOsqueryBinary. It defaults to
// os/exec.LookPath and is overridable from tests so binary discovery can be
// exercised without depending on what is installed on the test host (F026 in
// TECH_DEBT_AUDIT.md).
var lookPath = osexec.LookPath

// findOsqueryBinary searches for the osqueryi binary.
//
// Resolution order: explicit absolute paths in osqueryPaths first (matches the
// "use the system package's location if available" expectation on
// Fedora/RHEL/Debian), then PATH lookup for the bare "osqueryi" name (covers
// Homebrew/Linuxbrew, Nix, Snap, manual installs).
func findOsqueryBinary() string {
	for _, path := range osqueryPaths {
		if _, err := lookPath(path); err == nil {
			return path
		}
	}
	if path, err := lookPath("osqueryi"); err == nil {
		return path
	}
	return ""
}

// ListTables returns a list of available osquery tables.
func (c *Client) ListTables(ctx context.Context) ([]string, error) {
	output, err := c.execQuery(ctx, ".tables")
	if err != nil {
		return nil, err
	}

	var tables []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		// Skip empty lines and header lines
		if line == "" || strings.HasPrefix(line, "=>") || strings.HasPrefix(line, "+") {
			continue
		}
		// Remove leading "=>" if present
		line = strings.TrimPrefix(line, "=> ")
		if line != "" {
			tables = append(tables, line)
		}
	}
	return tables, nil
}

// tableSQL returns custom SQL for tables that need JOINs or special handling.
var tableSQL = map[string]string{
	"authorized_keys": "SELECT authorized_keys.* FROM users JOIN authorized_keys USING (uid)",
}

// Query executes an osquery SQL query and returns the results.
func (c *Client) Query(ctx context.Context, query *pb.OSQuery) (*pb.OSQueryResult, error) {
	var sql string
	if query.RawSql != "" {
		sql = query.RawSql
	} else if custom, ok := tableSQL[query.Table]; ok {
		sql = custom
	} else {
		if !validTableName.MatchString(query.Table) {
			return &pb.OSQueryResult{
				QueryId: query.QueryId,
				Success: false,
				Error:   fmt.Sprintf("invalid table name: %q", query.Table),
			}, nil
		}
		if isSensitiveTable(query.Table) {
			return &pb.OSQueryResult{
				QueryId: query.QueryId,
				Success: false,
				Error:   fmt.Sprintf("table %q is not permitted", query.Table),
			}, nil
		}
		sql = fmt.Sprintf("SELECT * FROM %s", query.Table)
	}

	rows, err := c.QuerySQL(ctx, sql)
	if err != nil {
		return &pb.OSQueryResult{
			QueryId: query.QueryId,
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.OSQueryResult{
		QueryId: query.QueryId,
		Success: true,
		Rows:    rows,
	}, nil
}

// QuerySQL executes a raw SQL query against osquery.
func (c *Client) QuerySQL(ctx context.Context, sql string) ([]*pb.OSQueryRow, error) {
	output, err := c.execQuery(ctx, sql)
	if err != nil {
		return nil, err
	}

	var results []map[string]string
	if err := json.Unmarshal([]byte(output), &results); err != nil {
		return nil, fmt.Errorf("failed to parse osquery output: %w", err)
	}

	rows := make([]*pb.OSQueryRow, 0, len(results))
	for _, result := range results {
		rows = append(rows, &pb.OSQueryRow{Data: result})
	}

	return rows, nil
}

// QueryTable queries a specific table by name.
func (c *Client) QueryTable(ctx context.Context, tableName string) ([]*pb.OSQueryRow, error) {
	sql, ok := tableSQL[tableName]
	if !ok {
		if !validTableName.MatchString(tableName) {
			return nil, fmt.Errorf("invalid table name: %q", tableName)
		}
		if isSensitiveTable(tableName) {
			return nil, fmt.Errorf("table %q is not permitted", tableName)
		}
		sql = fmt.Sprintf("SELECT * FROM %s", tableName)
	}
	return c.QuerySQL(ctx, sql)
}

// execQuery executes an osquery command (escalated through the Runner) and
// returns its stdout.
func (c *Client) execQuery(ctx context.Context, query string) (string, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}

	args := []string{}
	if strings.HasPrefix(query, ".") {
		args = append(args, query)
	} else {
		args = append(args, "--json", query)
	}

	res, err := c.r.Run(ctx, exec.Command{Name: c.binaryPath, Args: args, Escalate: true})
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrQueryFailed, err)
	}
	if res.ExitCode != 0 {
		if stderr := strings.TrimSpace(res.Stderr); stderr != "" {
			return "", fmt.Errorf("%w: %s", ErrQueryFailed, stderr)
		}
		return "", fmt.Errorf("%w: exit code %d", ErrQueryFailed, res.ExitCode)
	}

	return strings.TrimSpace(res.Stdout), nil
}
