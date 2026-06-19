package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/fs"
)

// fakeFS is a hermetic fsManager for the firewalld backend's service-XML writes,
// installed via the newFS seam by useFS. nil closures default to a success no-op.
type fakeFS struct {
	writeFn  func(path string, data []byte, opts fs.WriteOptions) error
	removeFn func(path string) error
}

func (f *fakeFS) WriteFile(_ context.Context, path string, data []byte, opts fs.WriteOptions) error {
	if f.writeFn != nil {
		return f.writeFn(path, data, opts)
	}
	return nil
}

func (f *fakeFS) Remove(_ context.Context, path string) error {
	if f.removeFn != nil {
		return f.removeFn(path)
	}
	return nil
}

// useFS points the newFS seam at f for the rest of the test (paired with
// swapFirewalldSeams, which restores newFS on cleanup).
func useFS(f *fakeFS) { newFS = func(exec.Runner) (fsManager, error) { return f, nil } }

// =============================================================================
// nftables — apply/remove/list driven by a recordingRunner (no kernel).
// =============================================================================

// nftListJSONWith builds an `nft -j list` envelope carrying one rule with the
// given comment/handle so the idempotency + List paths can be exercised.
func nftListJSONWith(comment string, handle int) string {
	return `{"nftables":[
		{"table":{"family":"inet","name":"app_filter","handle":1}},
		{"chain":{"family":"inet","table":"app_filter","name":"input","handle":2}},
		{"rule":{"family":"inet","table":"app_filter","chain":"input","handle":` +
		itoa(handle) + `,"comment":"` + comment + `","expr":[
			{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22}},
			{"accept":null}
		]}}
	]}`
}

func TestNftables_ApplyRule_NewRule(t *testing.T) {
	r := &recordingRunner{}
	r.push(exec.Result{ExitCode: 1}, nil) // nft list: table missing
	r.pushOut("")                         // nft -f -: ok
	m := newMgr(t, Nftables, "app", r)

	if err := m.ApplyRule(context.Background(), Rule{ID: "ssh", Allow: true, Protocol: ProtocolTCP, Port: 22}); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 2 {
		t.Fatalf("ran %d commands, want 2 (list + apply)", len(r.calls))
	}
	if got := r.argvOf(0); got != "nft -j list table inet app_filter" {
		t.Errorf("list argv = %q", got)
	}
	script := r.calls[1].stdin
	for _, want := range []string{
		"add table inet app_filter",
		"add chain inet app_filter input",
		`add rule inet app_filter input tcp dport 22 accept comment "ssh"`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("apply script missing %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "delete rule") {
		t.Errorf("new rule must not emit a delete:\n%s", script)
	}
}

func TestNftables_ApplyRule_ReplacesExisting(t *testing.T) {
	r := &recordingRunner{}
	r.pushOut(nftListJSONWith("ssh", 7)) // existing rule with handle 7
	r.pushOut("")                        // apply ok
	m := newMgr(t, Nftables, "app", r)

	if err := m.ApplyRule(context.Background(), Rule{ID: "ssh", Allow: false, Protocol: ProtocolUDP, Port: 53}); err != nil {
		t.Fatal(err)
	}
	script := r.calls[1].stdin
	if !strings.Contains(script, "delete rule inet app_filter input handle 7") {
		t.Errorf("replace must delete the old handle 7 in the same batch:\n%s", script)
	}
	if !strings.Contains(script, `udp dport 53 drop comment "ssh"`) {
		t.Errorf("replacement rule body wrong:\n%s", script)
	}
}

func TestNftables_ApplyRule_PortWithoutProtocolRejected(t *testing.T) {
	r := &recordingRunner{}
	r.push(exec.Result{ExitCode: 1}, nil) // list: no table
	m := newMgr(t, Nftables, "app", r)
	err := m.ApplyRule(context.Background(), Rule{ID: "bad", Allow: true, Protocol: ProtocolAny, Port: 22})
	if !errors.Is(err, ErrInvalidRule) {
		t.Errorf("err = %v, want ErrInvalidRule (port without protocol)", err)
	}
	// The build (and rejection) happens after a read-only list probe; the
	// mutating `nft -f -` must never run.
	for _, c := range r.calls {
		if strings.Contains(strings.Join(c.cmd.Args, " "), "-f") {
			t.Error("an untranslatable rule reached the mutating nft -f - call")
		}
	}
}

func TestNftables_ApplyRule_RunFailure(t *testing.T) {
	r := &recordingRunner{}
	r.push(exec.Result{ExitCode: 1}, nil)                         // list: no table
	r.push(exec.Result{ExitCode: 1, Stderr: "syntax error"}, nil) // nft -f - fails
	m := newMgr(t, Nftables, "app", r)
	if err := m.ApplyRule(context.Background(), Rule{ID: "ssh", Allow: true, Protocol: ProtocolTCP, Port: 22}); err == nil ||
		!strings.Contains(err.Error(), "nft -f -") {
		t.Errorf("err = %v, want a wrapped nft -f - failure", err)
	}
}

func TestNftables_RemoveRule(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		r := &recordingRunner{}
		r.pushOut(nftListJSONWith("ssh", 9)) // list
		r.pushOut("")                        // delete run
		m := newMgr(t, Nftables, "app", r)
		if err := m.RemoveRule(context.Background(), "ssh"); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(r.calls[1].stdin, "delete rule inet app_filter input handle 9") {
			t.Errorf("remove script = %q", r.calls[1].stdin)
		}
	})
	t.Run("no table is a no-op", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{ExitCode: 1}, nil) // list: missing table
		m := newMgr(t, Nftables, "app", r)
		if err := m.RemoveRule(context.Background(), "ssh"); err != nil {
			t.Fatal(err)
		}
		if len(r.calls) != 1 {
			t.Errorf("ran %d commands, want 1 (list only)", len(r.calls))
		}
	})
	t.Run("rule absent is a no-op", func(t *testing.T) {
		r := &recordingRunner{}
		r.pushOut(nftListJSONWith("other", 3)) // list has a different rule
		m := newMgr(t, Nftables, "app", r)
		if err := m.RemoveRule(context.Background(), "ssh"); err != nil {
			t.Fatal(err)
		}
		if len(r.calls) != 1 {
			t.Errorf("ran %d commands, want 1 (list only, no delete)", len(r.calls))
		}
	})
}

func TestNftables_List(t *testing.T) {
	t.Run("returns managed rules", func(t *testing.T) {
		r := &recordingRunner{}
		r.pushOut(nftListJSONWith("web-https", 9))
		m := newMgr(t, Nftables, "app", r)
		rules, err := m.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(rules) != 1 || rules[0].ID != "web-https" || rules[0].Port != 22 {
			t.Errorf("rules = %+v", rules)
		}
	})
	t.Run("no table → empty", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{ExitCode: 1}, nil)
		m := newMgr(t, Nftables, "app", r)
		rules, err := m.List(context.Background())
		if err != nil || len(rules) != 0 {
			t.Errorf("List = (%v,%v), want (nil,nil)", rules, err)
		}
	})
}

// =============================================================================
// firewalld — apply/remove/list with the fs seams stubbed.
// =============================================================================

func swapFirewalldSeams(t *testing.T) {
	t.Helper()
	on, ord := newFS, readFile
	t.Cleanup(func() { newFS, readFile = on, ord })
}

func TestFirewalld_ApplyRule_Happy(t *testing.T) {
	swapFirewalldSeams(t)
	var wrotePath, wroteBody string
	useFS(&fakeFS{writeFn: func(path string, data []byte, _ fs.WriteOptions) error {
		wrotePath, wroteBody = path, string(data)
		return nil
	}})
	r := &recordingRunner{}
	r.pushOut("public\n") // --get-default-zone
	r.pushOut("")         // --reload
	r.pushOut("")         // --add-service
	r.pushOut("")         // --reload (post-enable)
	m := newMgr(t, Firewalld, "app", r)

	if err := m.ApplyRule(context.Background(), Rule{ID: "https", Allow: true, Protocol: ProtocolTCP, Port: 443}); err != nil {
		t.Fatal(err)
	}
	if wrotePath != "/etc/firewalld/services/app-https.xml" {
		t.Errorf("service path = %q", wrotePath)
	}
	if !strings.Contains(wroteBody, `<port port="443" protocol="tcp"/>`) {
		t.Errorf("service xml missing port element:\n%s", wroteBody)
	}
	if got := r.argvOf(2); got != "firewall-cmd --permanent --zone=public --add-service=app-https" {
		t.Errorf("add-service argv = %q", got)
	}
	if len(r.calls) != 4 {
		t.Errorf("ran %d commands, want 4 (zone, reload, add, reload)", len(r.calls))
	}
}

func TestFirewalld_ApplyRule_ScopeRejections(t *testing.T) {
	cases := map[string]Rule{
		"deny":      {ID: "r", Allow: false, Protocol: ProtocolTCP, Port: 1},
		"source":    {ID: "r", Allow: true, Protocol: ProtocolTCP, Port: 1, Source: "10.0.0.0/8"},
		"dest":      {ID: "r", Allow: true, Protocol: ProtocolTCP, Port: 1, Dest: "10.0.0.1"},
		"any proto": {ID: "r", Allow: true, Protocol: ProtocolAny, Port: 1},
		"port zero": {ID: "r", Allow: true, Protocol: ProtocolTCP, Port: 0},
	}
	for name, rule := range cases {
		t.Run(name, func(t *testing.T) {
			r := &recordingRunner{}
			m := newMgr(t, Firewalld, "app", r)
			if err := m.ApplyRule(context.Background(), rule); !errors.Is(err, ErrInvalidRule) {
				t.Errorf("err = %v, want ErrInvalidRule", err)
			}
			if len(r.calls) != 0 {
				t.Errorf("ran %d commands for an out-of-scope rule; scope check must precede exec", len(r.calls))
			}
		})
	}
}

func TestFirewalld_ApplyRule_Failures(t *testing.T) {
	t.Run("get-default-zone fails", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{ExitCode: 1, Stderr: "no daemon"}, nil)
		m := newMgr(t, Firewalld, "app", r)
		if err := m.ApplyRule(context.Background(), Rule{ID: "r", Allow: true, Protocol: ProtocolTCP, Port: 1}); err == nil ||
			!strings.Contains(err.Error(), "get-default-zone") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("empty zone", func(t *testing.T) {
		r := &recordingRunner{}
		r.pushOut("   \n")
		m := newMgr(t, Firewalld, "app", r)
		if err := m.ApplyRule(context.Background(), Rule{ID: "r", Allow: true, Protocol: ProtocolTCP, Port: 1}); err == nil ||
			!strings.Contains(err.Error(), "empty") {
			t.Errorf("err = %v, want the empty-zone error", err)
		}
	})
	t.Run("writeFileAtomic fails", func(t *testing.T) {
		swapFirewalldSeams(t)
		useFS(&fakeFS{writeFn: func(string, []byte, fs.WriteOptions) error {
			return errors.New("disk full")
		}})
		r := &recordingRunner{}
		r.pushOut("public\n")
		m := newMgr(t, Firewalld, "app", r)
		if err := m.ApplyRule(context.Background(), Rule{ID: "r", Allow: true, Protocol: ProtocolTCP, Port: 1}); err == nil ||
			!strings.Contains(err.Error(), "write service xml") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("reload fails", func(t *testing.T) {
		swapFirewalldSeams(t)
		useFS(&fakeFS{})
		r := &recordingRunner{}
		r.pushOut("public\n")                 // zone
		r.push(exec.Result{ExitCode: 1}, nil) // reload fails
		m := newMgr(t, Firewalld, "app", r)
		if err := m.ApplyRule(context.Background(), Rule{ID: "r", Allow: true, Protocol: ProtocolTCP, Port: 1}); err == nil ||
			!strings.Contains(err.Error(), "--reload") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("add-service fails", func(t *testing.T) {
		swapFirewalldSeams(t)
		useFS(&fakeFS{})
		r := &recordingRunner{}
		r.pushOut("public\n")                 // zone
		r.pushOut("")                         // reload
		r.push(exec.Result{ExitCode: 1}, nil) // add-service fails
		m := newMgr(t, Firewalld, "app", r)
		if err := m.ApplyRule(context.Background(), Rule{ID: "r", Allow: true, Protocol: ProtocolTCP, Port: 1}); err == nil ||
			!strings.Contains(err.Error(), "add-service") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("post-enable reload fails", func(t *testing.T) {
		swapFirewalldSeams(t)
		useFS(&fakeFS{})
		r := &recordingRunner{}
		r.pushOut("public\n")                 // zone
		r.pushOut("")                         // reload
		r.pushOut("")                         // add-service
		r.push(exec.Result{ExitCode: 1}, nil) // post-enable reload fails
		m := newMgr(t, Firewalld, "app", r)
		if err := m.ApplyRule(context.Background(), Rule{ID: "r", Allow: true, Protocol: ProtocolTCP, Port: 1}); err == nil ||
			!strings.Contains(err.Error(), "post-enable") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestFirewalld_RemoveRule(t *testing.T) {
	t.Run("enabled → removed", func(t *testing.T) {
		swapFirewalldSeams(t)
		var removed string
		useFS(&fakeFS{removeFn: func(path string) error { removed = path; return nil }})
		r := &recordingRunner{}
		r.pushOut("public\n")        // zone
		r.pushOut("app-https ssh\n") // list-services (svc enabled)
		r.pushOut("")                // remove-service
		r.pushOut("")                // reload
		m := newMgr(t, Firewalld, "app", r)
		if err := m.RemoveRule(context.Background(), "https"); err != nil {
			t.Fatal(err)
		}
		if got := r.argvOf(2); got != "firewall-cmd --permanent --zone=public --remove-service=app-https" {
			t.Errorf("remove argv = %q", got)
		}
		if removed != "/etc/firewalld/services/app-https.xml" {
			t.Errorf("removed path = %q", removed)
		}
	})
	t.Run("not enabled → skip remove, still cleans + reloads", func(t *testing.T) {
		swapFirewalldSeams(t)
		useFS(&fakeFS{})
		r := &recordingRunner{}
		r.pushOut("public\n") // zone
		r.pushOut("ssh\n")    // list-services (svc absent)
		r.pushOut("")         // reload
		m := newMgr(t, Firewalld, "app", r)
		if err := m.RemoveRule(context.Background(), "https"); err != nil {
			t.Fatal(err)
		}
		if len(r.calls) != 3 {
			t.Errorf("ran %d commands, want 3 (zone, list, reload — no remove)", len(r.calls))
		}
	})
	t.Run("list-services fails", func(t *testing.T) {
		r := &recordingRunner{}
		r.pushOut("public\n")
		r.push(exec.Result{ExitCode: 1}, nil) // list-services
		m := newMgr(t, Firewalld, "app", r)
		if err := m.RemoveRule(context.Background(), "https"); err == nil ||
			!strings.Contains(err.Error(), "list-services") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("RemoveStrict hard failure", func(t *testing.T) {
		swapFirewalldSeams(t)
		useFS(&fakeFS{removeFn: func(string) error { return errors.New("permission denied") }})
		r := &recordingRunner{}
		r.pushOut("public\n")
		r.pushOut("ssh\n") // not enabled
		m := newMgr(t, Firewalld, "app", r)
		if err := m.RemoveRule(context.Background(), "https"); err == nil ||
			!strings.Contains(err.Error(), "remove") {
			t.Errorf("err = %v, want a wrapped RemoveStrict failure", err)
		}
	})
	t.Run("zone lookup fails", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{ExitCode: 1}, nil)
		m := newMgr(t, Firewalld, "app", r)
		if err := m.RemoveRule(context.Background(), "https"); err == nil {
			t.Error("RemoveRule continued past a zone-lookup failure")
		}
	})
}

func TestFirewalld_List(t *testing.T) {
	t.Run("reconstructs from xml", func(t *testing.T) {
		swapFirewalldSeams(t)
		readFile = func(path string) ([]byte, error) {
			if strings.HasSuffix(path, "app-https.xml") {
				return []byte(firewalldServiceXML("app", Rule{ID: "https", Allow: true, Protocol: ProtocolTCP, Port: 443})), nil
			}
			return nil, errors.New("missing")
		}
		r := &recordingRunner{}
		r.pushOut("public\n")                 // zone
		r.pushOut("app-https app-gone ssh\n") // list-services
		m := newMgr(t, Firewalld, "app", r)
		rules, err := m.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		// app-https reconstructs; app-gone's xml is missing → skipped; ssh isn't ours.
		if len(rules) != 1 || rules[0].ID != "https" || rules[0].Port != 443 {
			t.Errorf("rules = %+v, want just https/443", rules)
		}
	})
	t.Run("zone fails", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{ExitCode: 1}, nil)
		m := newMgr(t, Firewalld, "app", r)
		if _, err := m.List(context.Background()); err == nil {
			t.Error("List continued past a zone failure")
		}
	})
	t.Run("list-services fails", func(t *testing.T) {
		r := &recordingRunner{}
		r.pushOut("public\n")
		r.push(exec.Result{ExitCode: 1}, nil)
		m := newMgr(t, Firewalld, "app", r)
		if _, err := m.List(context.Background()); err == nil ||
			!strings.Contains(err.Error(), "list-services") {
			t.Errorf("err = %v", err)
		}
	})
}

// =============================================================================
// ufw — apply/remove/list driven by a recordingRunner.
// =============================================================================

// ufwStatusWith renders a minimal `ufw status numbered` body with one numbered
// rule carrying the given comment.
func ufwStatusWith(num int, to, comment string) string {
	return "Status: active\n\n" +
		"     To                         Action      From\n" +
		"     --                         ------      ----\n" +
		"[ " + itoa(num) + "] " + to + "                     ALLOW IN    Anywhere                   # " + comment + "\n"
}

func TestUFW_ApplyRule_NewRule(t *testing.T) {
	r := &recordingRunner{}
	r.pushOut("Status: active\n") // status numbered: no existing rule
	r.pushOut("")                 // ufw allow ...
	m := newMgr(t, UFW, "app", r)
	if err := m.ApplyRule(context.Background(), Rule{ID: "ssh", Allow: true, Protocol: ProtocolTCP, Port: 22}); err != nil {
		t.Fatal(err)
	}
	if got := r.argvOf(1); got != "ufw allow 22/tcp comment app:ssh" {
		t.Errorf("add argv = %q", got)
	}
}

func TestUFW_ApplyRule_ReplacesExisting(t *testing.T) {
	r := &recordingRunner{}
	r.pushOut(ufwStatusWith(3, "22/tcp", "app:ssh")) // status shows existing rule #3
	r.pushOut("")                                    // ufw --force delete 3
	r.pushOut("")                                    // ufw allow ...
	m := newMgr(t, UFW, "app", r)
	if err := m.ApplyRule(context.Background(), Rule{ID: "ssh", Allow: true, Protocol: ProtocolTCP, Port: 22}); err != nil {
		t.Fatal(err)
	}
	if got := r.argvOf(1); got != "ufw --force delete 3" {
		t.Errorf("delete argv = %q", got)
	}
}

func TestUFW_ApplyRule_DeleteExistingFails(t *testing.T) {
	r := &recordingRunner{}
	r.pushOut(ufwStatusWith(3, "22/tcp", "app:ssh"))
	r.push(exec.Result{ExitCode: 1}, nil) // delete fails
	m := newMgr(t, UFW, "app", r)
	if err := m.ApplyRule(context.Background(), Rule{ID: "ssh", Allow: true, Protocol: ProtocolTCP, Port: 22}); err == nil ||
		!strings.Contains(err.Error(), "delete existing rule") {
		t.Errorf("err = %v", err)
	}
}

func TestUFW_ApplyRule_StatusErrorStillAdds(t *testing.T) {
	r := &recordingRunner{}
	r.push(exec.Result{ExitCode: 1}, nil) // status fails (inactive) → skip delete
	r.pushOut("")                         // add still runs
	m := newMgr(t, UFW, "app", r)
	if err := m.ApplyRule(context.Background(), Rule{ID: "ssh", Allow: true, Protocol: ProtocolTCP, Port: 22}); err != nil {
		t.Fatal(err)
	}
	if got := r.argvOf(1); got != "ufw allow 22/tcp comment app:ssh" {
		t.Errorf("add argv = %q", got)
	}
}

func TestUFW_ApplyRule_AddFails(t *testing.T) {
	r := &recordingRunner{}
	r.pushOut("Status: active\n")
	r.push(exec.Result{ExitCode: 1, Stderr: "bad rule"}, nil)
	m := newMgr(t, UFW, "app", r)
	if err := m.ApplyRule(context.Background(), Rule{ID: "ssh", Allow: true, Protocol: ProtocolTCP, Port: 22}); err == nil ||
		!strings.Contains(err.Error(), "ufw allow") {
		t.Errorf("err = %v", err)
	}
}

func TestUFW_ApplyRule_ScopeRejection(t *testing.T) {
	r := &recordingRunner{}
	m := newMgr(t, UFW, "app", r)
	// Port without a concrete protocol is rejected before any exec.
	if err := m.ApplyRule(context.Background(), Rule{ID: "bad", Allow: true, Protocol: ProtocolAny, Port: 22}); !errors.Is(err, ErrInvalidRule) {
		t.Errorf("err = %v, want ErrInvalidRule", err)
	}
	if len(r.calls) != 0 {
		t.Error("ran a command for a port-without-protocol rule")
	}
}

func TestUFW_RemoveRule(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		r := &recordingRunner{}
		r.pushOut(ufwStatusWith(2, "22/tcp", "app:ssh"))
		r.pushOut("") // delete
		m := newMgr(t, UFW, "app", r)
		if err := m.RemoveRule(context.Background(), "ssh"); err != nil {
			t.Fatal(err)
		}
		if got := r.argvOf(1); got != "ufw --force delete 2" {
			t.Errorf("delete argv = %q", got)
		}
	})
	t.Run("inactive ufw is a no-op", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{ExitCode: 1}, nil) // status fails
		m := newMgr(t, UFW, "app", r)
		if err := m.RemoveRule(context.Background(), "ssh"); err != nil {
			t.Fatal(err)
		}
		if len(r.calls) != 1 {
			t.Errorf("ran %d commands, want 1 (status only)", len(r.calls))
		}
	})
	t.Run("not found is a no-op", func(t *testing.T) {
		r := &recordingRunner{}
		r.pushOut(ufwStatusWith(2, "22/tcp", "other:ssh")) // different namespace
		m := newMgr(t, UFW, "app", r)
		if err := m.RemoveRule(context.Background(), "ssh"); err != nil {
			t.Fatal(err)
		}
		if len(r.calls) != 1 {
			t.Errorf("ran %d commands, want 1 (status only, no delete)", len(r.calls))
		}
	})
	t.Run("delete fails", func(t *testing.T) {
		r := &recordingRunner{}
		r.pushOut(ufwStatusWith(2, "22/tcp", "app:ssh"))
		r.push(exec.Result{ExitCode: 1}, nil)
		m := newMgr(t, UFW, "app", r)
		if err := m.RemoveRule(context.Background(), "ssh"); err == nil ||
			!strings.Contains(err.Error(), "--force delete") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestUFW_List(t *testing.T) {
	t.Run("parses namespaced rules", func(t *testing.T) {
		r := &recordingRunner{}
		r.pushOut(ufwStatusWith(1, "22/tcp", "app:ssh"))
		m := newMgr(t, UFW, "app", r)
		rules, err := m.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(rules) != 1 || rules[0].ID != "ssh" || rules[0].Port != 22 || rules[0].Protocol != ProtocolTCP {
			t.Errorf("rules = %+v", rules)
		}
	})
	t.Run("inactive → empty", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{ExitCode: 1}, nil)
		m := newMgr(t, UFW, "app", r)
		rules, err := m.List(context.Background())
		if err != nil || len(rules) != 0 {
			t.Errorf("List = (%v,%v), want empty", rules, err)
		}
	})
}
