package osquery

import (
	"context"
	"testing"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

type osqueryPolicyAction int

const (
	osqueryAllowedTable osqueryPolicyAction = iota
	osqueryDeniedTable
	osqueryRawDeniedTable
	osqueryRawDeniedTableViaCTE
	osqueryRawProcessEnvSecret
)

type osqueryPolicyStep struct {
	name       string
	action     osqueryPolicyAction
	wantReject bool
}

// TestOSQueryPolicySecurityMachine models the osquery boundary as a policy
// automaton. Remote query input may reach the privileged osquery binary only if
// the resolved SQL cannot touch credential-bearing tables; every rejected state
// must fail before Runner execution.
func TestOSQueryPolicySecurityMachine(t *testing.T) {
	steps := []osqueryPolicyStep{
		{name: "allowed inventory table reaches osquery", action: osqueryAllowedTable},
		{name: "structured sensitive table is rejected", action: osqueryDeniedTable, wantReject: true},
		{name: "raw shadow table is rejected", action: osqueryRawDeniedTable, wantReject: true},
		{name: "raw CTE shadow table is rejected", action: osqueryRawDeniedTableViaCTE, wantReject: true},
		{name: "raw process environment table is rejected", action: osqueryRawProcessEnvSecret, wantReject: true},
	}

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			r := exectest.New(exec.Direct)
			if !step.wantReject {
				r.Push(exec.Result{Stdout: `[{"name":"linux"}]`}, nil)
			}
			c := &client{binaryPath: "/usr/bin/osqueryi", r: r}
			res, err := c.Query(context.Background(), osqueryQueryForAction(step.action))
			if err != nil {
				t.Fatalf("Query returned Go error: %v", err)
			}
			if step.wantReject {
				if res.GetSuccess() || res.GetError() == "" {
					t.Fatalf("%s returned %+v, want folded policy rejection", step.name, res)
				}
				if calls := r.Calls(); len(calls) != 0 {
					t.Fatalf("%s reached privileged osquery execution: %+v", step.name, calls)
				}
				return
			}
			if !res.GetSuccess() {
				t.Fatalf("%s returned %+v, want success", step.name, res)
			}
			if calls := r.Calls(); len(calls) != 1 || !calls[0].Escalate {
				t.Fatalf("%s calls = %+v, want one escalated osquery call", step.name, calls)
			}
		})
	}
}

func osqueryQueryForAction(action osqueryPolicyAction) *pb.OSQuery {
	switch action {
	case osqueryAllowedTable:
		return &pb.OSQuery{QueryId: "q", Table: "os_version"}
	case osqueryDeniedTable:
		return &pb.OSQuery{QueryId: "q", Table: "shadow"}
	case osqueryRawDeniedTable:
		return &pb.OSQuery{QueryId: "q", RawSql: "SELECT * FROM shadow"}
	case osqueryRawDeniedTableViaCTE:
		return &pb.OSQuery{QueryId: "q", RawSql: "WITH stolen AS (SELECT * FROM shadow) SELECT * FROM stolen"}
	case osqueryRawProcessEnvSecret:
		return &pb.OSQuery{QueryId: "q", RawSql: "SELECT * FROM process_envs WHERE key LIKE '%TOKEN%'"}
	default:
		return &pb.OSQuery{QueryId: "q", Table: "os_version"}
	}
}
