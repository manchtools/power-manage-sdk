package osquery

import (
	"context"
	"strings"
	"testing"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// The non-raw Query() table path must refuse known-sensitive tables even though
// they match validTableName, and must do so BEFORE building or running any SQL.
// The sensitive cases are sourced from intent (credential-bearing osquery
// tables), not from the validTableName regex. The execPrivileged seam records
// every execution so the test can prove the deny path runs zero queries.
func TestQuery_DeniesSensitiveTables(t *testing.T) {
	orig := execPrivileged
	t.Cleanup(func() { execPrivileged = orig })

	var executed []string // args actually sent to the osquery binary
	execPrivileged = func(ctx context.Context, name string, args ...string) (*sysexec.Result, error) {
		executed = append(executed, strings.Join(args, " "))
		return &sysexec.Result{Stdout: "[]"}, nil // valid empty JSON result set
	}

	c := &Client{binaryPath: "/usr/bin/osqueryi"}
	ctx := context.Background()

	// present-but-wrong: each sensitive table is regex-valid but policy-forbidden.
	for table := range sensitiveTables {
		res, err := c.Query(ctx, &pb.OSQuery{QueryId: "q", Table: table})
		if err != nil {
			t.Fatalf("Query(%q) returned a transport error: %v", table, err)
		}
		if res.Success {
			t.Errorf("Query(%q) succeeded; a sensitive table must be refused", table)
		}
		if !strings.Contains(res.Error, table) || !strings.Contains(res.Error, "not permitted") {
			t.Errorf("Query(%q) error = %q, want it to name the table as not permitted", table, res.Error)
		}
	}
	if len(executed) != 0 {
		t.Errorf("a denied table must execute no query, but %d ran: %v", len(executed), executed)
	}

	// ABSENT: empty table and empty RawSql → the existing invalid-name rejection.
	res, err := c.Query(ctx, &pb.OSQuery{QueryId: "q", Table: ""})
	if err != nil {
		t.Fatalf("Query(empty) transport error: %v", err)
	}
	if res.Success || !strings.Contains(res.Error, "invalid table name") {
		t.Errorf("empty table = %+v, want the invalid-name rejection", res)
	}

	// correct: a benign table builds and runs SELECT * FROM <table> exactly once.
	executed = nil
	res, err = c.Query(ctx, &pb.OSQuery{QueryId: "q", Table: "os_version"})
	if err != nil {
		t.Fatalf("Query(os_version) error: %v", err)
	}
	if !res.Success {
		t.Errorf("a non-sensitive table must be queryable, got %+v", res)
	}
	if len(executed) != 1 || !strings.Contains(executed[0], "SELECT * FROM os_version") {
		t.Errorf("expected exactly one os_version query, got %v", executed)
	}
}

// Self-discovering guard: the deny-list must be non-empty, every member must be
// enforced by isSensitiveTable (including case/whitespace variants), and sample
// benign tables must stay queryable. Adding a table to sensitiveTables is
// automatically covered; emptying the set or dropping enforcement fails here.
func TestSensitiveTables_PolicyNonEmptyAndEnforced(t *testing.T) {
	if len(sensitiveTables) == 0 {
		t.Fatal("the sensitive-table deny-list must not be empty")
	}
	for table := range sensitiveTables {
		if !isSensitiveTable(table) {
			t.Errorf("%q is in sensitiveTables but isSensitiveTable returns false", table)
		}
		if !isSensitiveTable(strings.ToUpper(table)) || !isSensitiveTable(" "+table+" ") {
			t.Errorf("%q case/whitespace variants must also be refused", table)
		}
	}
	for _, benign := range []string{"os_version", "uptime", "system_info"} {
		if isSensitiveTable(benign) {
			t.Errorf("%q is a benign table and must stay queryable", benign)
		}
	}
}
