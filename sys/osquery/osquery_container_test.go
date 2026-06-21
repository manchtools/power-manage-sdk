//go:build container

// Container-based real-execution tests for the osquery Querier. The fake-runner
// unit tests feed captured osqueryi JSON; these run real `osqueryi --json`
// queries inside the container against the installed binary, so an osquery
// output-format change (the []map[string]string JSON shape, the `.tables`
// listing) is caught here. They also prove the security-critical sensitive-table
// deny-list against the REAL binary: the table path refuses every deny-listed
// table before exec, while the CA-signed RawSql escape hatch is intentionally
// NOT gated and runs the same table.
//
// Runs in the container-tests lane (root), so the Runner is Direct: Escalate is
// a no-op wrapper and osqueryi runs as the already-root process — the same shape
// production drives when the agent is root.
package osquery

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/sys/exec"
)

func realQuerier(t *testing.T) Querier {
	t.Helper()
	r, err := exec.NewRunner(exec.Direct)
	if err != nil {
		t.Fatalf("NewRunner(Direct): %v", err)
	}
	q, err := New(r)
	if err != nil {
		// In the with-osquery stage the binary is present (asserted at build
		// time); anywhere else this capability is simply not exercisable.
		t.Skipf("osquery not installed here: %v", err)
	}
	return q
}

func osqCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestQueryTable_OSVersion_Container runs a real `SELECT * FROM os_version` and
// pins the JSON round-trip: osqueryi must return exactly one row whose `name`
// column is populated. A change to osqueryi's --json shape breaks the
// []map[string]string parse and fails here.
func TestQueryTable_OSVersion_Container(t *testing.T) {
	rows, err := realQuerier(t).QueryTable(osqCtx(t), "os_version")
	if err != nil {
		t.Fatalf("QueryTable(os_version): %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("os_version returned %d rows, want 1", len(rows))
	}
	if name := rows[0].Data["name"]; name == "" {
		t.Errorf("os_version row missing/empty `name` column: %+v", rows[0].Data)
	}
}

// TestIsInstalled_Container: the live re-probe must see the binary baked into the
// image.
func TestIsInstalled_Container(t *testing.T) {
	if !realQuerier(t).IsInstalled(osqCtx(t)) {
		t.Error("IsInstalled = false, but osqueryi is installed in this image")
	}
}

// TestListTables_Container pins the `.tables` meta-command parse: the real
// listing must decode into a non-empty slice that includes well-known core
// tables. A format change to osqueryi's `.tables` output is caught here.
func TestListTables_Container(t *testing.T) {
	tables, err := realQuerier(t).ListTables(osqCtx(t))
	if err != nil {
		t.Fatalf("ListTables: %v", err)
	}
	if len(tables) == 0 {
		t.Fatal("ListTables returned no tables from real osqueryi `.tables`")
	}
	for _, want := range []string{"os_version", "processes"} {
		if !containsTable(tables, want) {
			t.Errorf("ListTables missing core table %q; got %d tables", want, len(tables))
		}
	}
}

// TestDenyList_RefusedBeforeExec_Container is SELF-DISCOVERING: it iterates the
// real sensitiveTables map (not a hardcoded copy), so a table added to the
// deny-list is automatically covered. Each must be refused by BOTH the
// QueryTable and Query table paths — and the refusal must be the policy error
// ("not permitted"), distinguishable from a query-execution failure, proving the
// gate fires BEFORE the binary is ever invoked.
func TestDenyList_RefusedBeforeExec_Container(t *testing.T) {
	q := realQuerier(t)
	ctx := osqCtx(t)
	if len(sensitiveTables) == 0 {
		t.Fatal("sensitiveTables is empty — deny-list coverage would be vacuous")
	}
	for table := range sensitiveTables {
		// QueryTable path: a Go error carrying the policy phrase.
		_, err := q.QueryTable(ctx, table)
		if err == nil {
			t.Errorf("QueryTable(%q): expected refusal, got nil error", table)
		} else if !strings.Contains(err.Error(), "not permitted") {
			t.Errorf("QueryTable(%q): want a 'not permitted' refusal, got %v", table, err)
		}
		// Query path: refusal folded into the result, never executed.
		res, err := q.Query(ctx, &pb.OSQuery{Table: table})
		if err != nil {
			t.Errorf("Query(%q): unexpected Go error: %v", table, err)
		}
		if res.GetSuccess() {
			t.Errorf("Query(%q): expected Success=false (refused), got success", table)
		}
		if !strings.Contains(res.GetError(), "not permitted") {
			t.Errorf("Query(%q): want a 'not permitted' refusal, got %q", table, res.GetError())
		}
	}
}

// mustDenyTables is the TEST-OWNED threat model: osquery tables that expose
// credential material or secrets and MUST be refused by the table path. It is
// listed here INDEPENDENTLY of the implementation's sensitiveTables map — that
// is the whole point. The map-driven test above proves "every denied table is
// refused"; it cannot prove "every table that SHOULD be denied is", because it
// reads the same map the implementation does, so dropping a table from the
// deny-list would silently drop it from the test too. This list is the fixed
// expectation that catches such a regression. Each entry is justified:
//   - shadow:        password hashes
//   - process_envs:  a process environment can carry secrets / tokens
//   - shell_history: pasted passwords / tokens land in command history
//   - crontab:       scheduled commands can embed credentials
//   - sudoers:       privilege policy; can name secret-bearing commands
var mustDenyTables = []string{"shadow", "process_envs", "shell_history", "crontab", "sudoers"}

// TestDenyList_ThreatModelComplete_Container is the INDEPENDENT companion to the
// map-driven deny-list test: every threat-model-sensitive table that the real
// osqueryi actually ships MUST be on the deny-list (isSensitiveTable) AND refused
// before exec. Because the expectation comes from the threat model rather than
// from sensitiveTables, this fails if the deny-list is regressed or
// under-specified — the case the map-driven test is structurally blind to.
func TestDenyList_ThreatModelComplete_Container(t *testing.T) {
	q := realQuerier(t)
	ctx := osqCtx(t)
	tables, err := q.ListTables(ctx)
	if err != nil {
		t.Fatalf("ListTables: %v", err)
	}

	checked := 0
	for _, want := range mustDenyTables {
		if !containsTable(tables, want) {
			// A given osqueryi build may not ship every table; only assert on
			// the ones actually present so the intersection is real, not vacuous.
			t.Logf("threat-model table %q absent from this osqueryi build; skipping", want)
			continue
		}
		if !isSensitiveTable(want) {
			t.Errorf("table %q is threat-model-sensitive but NOT on the deny-list (sensitiveTables) — deny-list regressed/under-specified", want)
		}
		if _, err := q.QueryTable(ctx, want); err == nil || !strings.Contains(err.Error(), "not permitted") {
			t.Errorf("QueryTable(%q): want a 'not permitted' refusal before exec, got %v", want, err)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("matches-zero: no threat-model table was present in the real .tables listing — the completeness check is vacuous (osquery build/parse problem?)")
	}
}

// TestRawSqlGated_Container proves against the real binary that RawSql is gated
// by the same credential-table deny-list as the table path: a raw query naming
// `shadow` is refused and osqueryi is never run. (Supersedes the prior WS4
// escape-hatch behaviour where signed RawSql bypassed the deny-list.)
func TestRawSqlGated_Container(t *testing.T) {
	res, err := realQuerier(t).Query(osqCtx(t), &pb.OSQuery{
		RawSql: "SELECT count(*) AS n FROM shadow",
	})
	if err != nil {
		t.Fatalf("Query(RawSql shadow count): unexpected Go error: %v", err)
	}
	if res.GetSuccess() || !strings.Contains(res.GetError(), "not permitted") {
		t.Fatalf("RawSql naming deny-listed `shadow` must be refused; got success=%v err=%q", res.GetSuccess(), res.GetError())
	}
	if len(res.GetRows()) != 0 {
		t.Fatalf("refused RawSql returned %d rows, want 0", len(res.GetRows()))
	}
}

// TestInvalidTableName_Container: a non-identifier table name is rejected on
// shape (before exec) by both table paths against the real binary.
func TestInvalidTableName_Container(t *testing.T) {
	q := realQuerier(t)
	ctx := osqCtx(t)
	const bad = "os_version; DROP TABLE x"
	if _, err := q.QueryTable(ctx, bad); err == nil || !strings.Contains(err.Error(), "invalid table name") {
		t.Errorf("QueryTable(%q): want 'invalid table name', got %v", bad, err)
	}
	res, err := q.Query(ctx, &pb.OSQuery{Table: bad})
	if err != nil {
		t.Errorf("Query(%q): unexpected Go error: %v", bad, err)
	}
	if res.GetSuccess() || !strings.Contains(res.GetError(), "invalid table name") {
		t.Errorf("Query(%q): want refused with 'invalid table name', got success=%v err=%q", bad, res.GetSuccess(), res.GetError())
	}
}

func containsTable(tables []string, want string) bool {
	for _, tbl := range tables {
		if tbl == want {
			return true
		}
	}
	return false
}
