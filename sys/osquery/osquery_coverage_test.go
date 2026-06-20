package osquery

import (
	"context"
	"strings"
	"testing"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

func TestListTables(t *testing.T) {
	r := exectest.New(exec.Direct)
	// REAL `osqueryi .tables` format: one table per line as "  => <name>"
	// (leading whitespace + "=> " prefix). The "=> " lines ARE the data — they
	// are the table names, not noise to skip. Blank lines are ignored. This
	// mirrors the captured real output the sys/osquery container test asserts
	// live; an earlier fake fed bare names + treated "=>" lines as skippable,
	// which inverted the contract and hid that the parser dropped every real
	// table.
	r.Push(exec.Result{Stdout: "  => os_version\n  => uptime\n\n  => system_info\n"}, nil)
	c := &client{binaryPath: "/usr/bin/osqueryi", r: r}
	tables, err := c.ListTables(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"os_version": true, "uptime": true, "system_info": true}
	if len(tables) != len(want) {
		t.Fatalf("tables = %v, want %d entries", tables, len(want))
	}
	for _, tb := range tables {
		if !want[tb] {
			t.Errorf("unexpected table %q", tb)
		}
		delete(want, tb)
	}
	if len(want) != 0 {
		t.Errorf("parser dropped tables: %v", want)
	}
	// `.tables` is a dot-command — passed bare, not via --json.
	if argv := strings.Join(r.Calls()[0].Args, " "); argv != ".tables" {
		t.Errorf("argv = %q, want bare `.tables`", argv)
	}
}

func TestListTables_ExecError(t *testing.T) {
	r := exectest.New(exec.Direct)
	r.Push(exec.Result{ExitCode: 1, Stderr: "boom"}, nil)
	c := &client{binaryPath: "/usr/bin/osqueryi", r: r}
	if _, err := c.ListTables(context.Background()); err == nil {
		t.Error("ListTables swallowed a query failure")
	}
}

func TestQuery_CustomTableSQL(t *testing.T) {
	r := exectest.New(exec.Direct)
	r.Push(exec.Result{Stdout: "[]"}, nil)
	c := &client{binaryPath: "/usr/bin/osqueryi", r: r}
	res, err := c.Query(context.Background(), &pb.OSQuery{QueryId: "q", Table: "authorized_keys"})
	if err != nil || !res.Success {
		t.Fatalf("Query(authorized_keys) = (%+v,%v)", res, err)
	}
	if argv := strings.Join(r.Calls()[0].Args, " "); !strings.Contains(argv, "JOIN authorized_keys USING (uid)") {
		t.Errorf("custom JOIN SQL not used: %q", argv)
	}
}

func TestQuery_RawSQLRefusesSensitiveTablesBeforeExec(t *testing.T) {
	r := exectest.New(exec.Direct)
	c := &client{binaryPath: "/usr/bin/osqueryi", r: r}
	res, err := c.Query(context.Background(), &pb.OSQuery{QueryId: "q", RawSql: "SELECT * FROM shadow"})
	if err != nil {
		t.Fatalf("Query returned Go error = %v, want folded result", err)
	}
	if res.GetSuccess() || res.GetError() == "" {
		t.Fatalf("Query(RawSql shadow) = %+v, want Success=false with a policy error", res)
	}
	if calls := r.Calls(); len(calls) != 0 {
		t.Fatalf("RawSql sensitive query ran %d command(s) before policy rejection: %+v", len(calls), calls)
	}
}

func TestQuery_QuerySQLErrorSurfacesInResult(t *testing.T) {
	r := exectest.New(exec.Direct)
	r.Push(exec.Result{Stdout: "not json"}, nil) // parse failure inside QuerySQL
	c := &client{binaryPath: "/usr/bin/osqueryi", r: r}
	res, err := c.Query(context.Background(), &pb.OSQuery{QueryId: "q", Table: "os_version"})
	if err != nil {
		t.Fatalf("Query should fold the SQL error into the result, not return it: %v", err)
	}
	if res.Success || res.Error == "" {
		t.Errorf("res = %+v, want Success=false with a populated Error", res)
	}
}

func TestQueryTable(t *testing.T) {
	t.Run("benign", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{Stdout: `[{"name":"x"}]`}, nil)
		c := &client{binaryPath: "/usr/bin/osqueryi", r: r}
		rows, err := c.QueryTable(context.Background(), "os_version")
		if err != nil || len(rows) != 1 {
			t.Fatalf("QueryTable = (%v,%v), want one row", rows, err)
		}
	})
	t.Run("custom tableSQL", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		r.Push(exec.Result{Stdout: "[]"}, nil)
		c := &client{binaryPath: "/usr/bin/osqueryi", r: r}
		if _, err := c.QueryTable(context.Background(), "authorized_keys"); err != nil {
			t.Fatal(err)
		}
		if argv := strings.Join(r.Calls()[0].Args, " "); !strings.Contains(argv, "JOIN authorized_keys") {
			t.Errorf("custom SQL not used: %q", argv)
		}
	})
	t.Run("invalid name rejected before exec", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		c := &client{binaryPath: "/usr/bin/osqueryi", r: r}
		if _, err := c.QueryTable(context.Background(), "bad name!"); err == nil {
			t.Error("QueryTable accepted an invalid name")
		}
		if len(r.Calls()) != 0 {
			t.Error("ran a query for an invalid table name")
		}
	})
	t.Run("sensitive table refused before exec", func(t *testing.T) {
		r := exectest.New(exec.Direct)
		c := &client{binaryPath: "/usr/bin/osqueryi", r: r}
		if _, err := c.QueryTable(context.Background(), "shadow"); err == nil {
			t.Error("QueryTable returned a sensitive table")
		}
		if len(r.Calls()) != 0 {
			t.Error("ran a query for a sensitive table")
		}
	})
}
