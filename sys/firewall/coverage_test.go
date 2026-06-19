package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// cmd.exec must surface a transport error (err != nil from the Runner), not just
// a non-zero exit. Driven through firewalld's zone lookup.
func TestCmdExec_TransportError(t *testing.T) {
	r := &recordingRunner{}
	r.push(exec.Result{}, errors.New("connection refused"))
	m := newMgr(t, Firewalld, "app", r)
	if _, err := m.List(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "get-default-zone") {
		t.Errorf("err = %v, want the transport error wrapped", err)
	}
}

// --- firewalld RemoveRule failure branches ---

func TestFirewalld_RemoveRule_RemoveServiceFails(t *testing.T) {
	r := &recordingRunner{}
	r.pushOut("public\n")                 // zone
	r.pushOut("app-https ssh\n")          // list-services (enabled)
	r.push(exec.Result{ExitCode: 1}, nil) // remove-service fails
	m := newMgr(t, Firewalld, "app", r)
	if err := m.RemoveRule(context.Background(), "https"); err == nil ||
		!strings.Contains(err.Error(), "remove-service") {
		t.Errorf("err = %v, want a wrapped remove-service failure", err)
	}
}

func TestFirewalld_RemoveRule_FinalReloadFails(t *testing.T) {
	swapFirewalldSeams(t)
	useFS(&fakeFS{})
	r := &recordingRunner{}
	r.pushOut("public\n")                 // zone
	r.pushOut("app-https ssh\n")          // list-services (enabled)
	r.pushOut("")                         // remove-service
	r.push(exec.Result{ExitCode: 1}, nil) // final reload fails
	m := newMgr(t, Firewalld, "app", r)
	if err := m.RemoveRule(context.Background(), "https"); err == nil ||
		!strings.Contains(err.Error(), "--reload") {
		t.Errorf("err = %v, want a wrapped reload failure", err)
	}
}

// firewalldReadServiceRule must reject XML that lacks a port/protocol (e.g. a
// file an operator hand-edited) rather than returning a half-populated rule.
func TestFirewalldReadServiceRule_MalformedSkipped(t *testing.T) {
	swapFirewalldSeams(t)
	readFile = func(string) ([]byte, error) {
		return []byte(`<?xml version="1.0"?><service><short>app-x</short></service>`), nil
	}
	if _, ok := firewalldReadServiceRule("app", "x"); ok {
		t.Error("firewalldReadServiceRule accepted XML with no port/protocol")
	}
}

// --- nftables helpers ---

func TestNftDeleteManagedTable(t *testing.T) {
	r := &recordingRunner{}
	n := &nftables{base: base{ns: "app", cmd: cmd{r: r}}}
	if err := n.nftDeleteManagedTable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.calls[0].stdin, "delete table inet app_filter") {
		t.Errorf("delete-table script = %q", r.calls[0].stdin)
	}
}

func TestNftBuildApplyScriptStrict_RejectsInvalidDest(t *testing.T) {
	_, err := nftBuildApplyScriptStrict("app", Rule{
		ID: "x", Allow: true, Protocol: ProtocolTCP, Port: 22,
		Source: "10.0.0.0/8", Dest: "not-an-ip",
	}, 0)
	if err == nil || !strings.Contains(err.Error(), "dest") {
		t.Errorf("err = %v, want a dest address-family failure", err)
	}
}

func TestNftParseRules_EdgeInputs(t *testing.T) {
	if rules, err := nftParseRules(nil); err != nil || rules != nil {
		t.Errorf("nftParseRules(nil) = (%v,%v), want (nil,nil)", rules, err)
	}
	if _, err := nftParseRules([]byte("not json")); err == nil {
		t.Error("nftParseRules(garbage) returned nil error")
	}
}

func TestNftParseRules_DropVerdict(t *testing.T) {
	input := `{"nftables":[{"rule":{"comment":"blockit","expr":[
		{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":53}},
		{"drop":null}
	]}}]}`
	rules, err := nftParseRules(json.RawMessage(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Allow || rules[0].Protocol != ProtocolUDP || rules[0].Port != 53 {
		t.Errorf("rules = %+v, want a single udp/53 drop", rules)
	}
}

func TestNftFindRuleHandle_EdgeInputs(t *testing.T) {
	if _, ok := nftFindRuleHandle(nil, "x"); ok {
		t.Error("nftFindRuleHandle(nil) reported found")
	}
	if _, ok := nftFindRuleHandle([]byte("not json"), "x"); ok {
		t.Error("nftFindRuleHandle(garbage) reported found")
	}
}

// --- ufw helpers ---

func TestUFWBuildAddArgs_ProtoOnly(t *testing.T) {
	// No port, no scope, concrete protocol → long form `from any to any proto`.
	args, err := ufwBuildAddArgs("app", Rule{ID: "x", Allow: true, Protocol: ProtocolTCP})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"allow", "from", "any", "to", "any", "proto", "tcp", "comment", "app:x"}
	assertArgsEqual(t, args, want)
}

func TestUFWFindRuleNumber_OverflowNumberSkipped(t *testing.T) {
	// A rule index too large for int overflows strconv.Atoi → the line is skipped
	// rather than crashing the lookup.
	status := "[ 99999999999999999999999999999] 22/tcp                  ALLOW IN    Anywhere                   # app:ssh"
	if _, ok := ufwFindRuleNumber(status, "app", "ssh"); ok {
		t.Error("ufwFindRuleNumber returned a match for an unparseable index")
	}
}

func TestUFWParseToColumn_Variants(t *testing.T) {
	var anywhere Rule
	ufwParseToColumn("Anywhere", &anywhere)
	if anywhere.Port != 0 || anywhere.Protocol != "" || anywhere.Dest != "" {
		t.Errorf("Anywhere mutated the rule: %+v", anywhere)
	}

	var barePort Rule
	ufwParseToColumn("53", &barePort)
	if barePort.Port != 53 {
		t.Errorf("bare port = %d, want 53", barePort.Port)
	}

	var dest Rule
	ufwParseToColumn("10.0.0.5", &dest)
	if dest.Dest != "10.0.0.5" {
		t.Errorf("dest = %q, want 10.0.0.5", dest.Dest)
	}
}
