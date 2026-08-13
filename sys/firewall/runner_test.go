package firewall

import (
	"context"
	"errors"
	"fmt"
	"os"
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
	// present models files already on disk, keyed by path. WriteFileExclusive
	// refuses those with fs.ErrExists exactly as the real one does, and a
	// successful exclusive create adds to the set — so a test can plant a
	// "foreign" definition and watch the backend correctly decline ownership.
	present map[string]bool
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

// WriteFileExclusive refuses a path already in `present` with fs.ErrExists and
// otherwise records the create. Default (nil map) is "nothing on disk", i.e. the
// common fresh-create case the existing firewalld tests were written for.
func (f *fakeFS) WriteFileExclusive(_ context.Context, path string, data []byte, opts fs.WriteOptions) error {
	if f.present[path] {
		return fmt.Errorf("write file %s: %w", path, fs.ErrExists)
	}
	if f.writeFn != nil {
		if err := f.writeFn(path, data, opts); err != nil {
			return err
		}
	}
	if f.present == nil {
		f.present = map[string]bool{}
	}
	f.present[path] = true
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
		// nft prints "No such file or directory" when the table is absent; that
		// is the only list failure RemoveRule may treat as "already absent".
		r.push(exec.Result{ExitCode: 1, Stderr: "Error: No such file or directory"}, nil)
		m := newMgr(t, Nftables, "app", r)
		if err := m.RemoveRule(context.Background(), "ssh"); err != nil {
			t.Fatal(err)
		}
		if len(r.calls) != 1 {
			t.Errorf("ran %d commands, want 1 (list only)", len(r.calls))
		}
	})
	t.Run("a real list failure is NOT swallowed as a no-op", func(t *testing.T) {
		r := &recordingRunner{}
		// Escalation denied / nft crash: RemoveRule must NOT report a successful
		// no-op (it did not prove the rule absent).
		r.push(exec.Result{ExitCode: 1, Stderr: "Operation not permitted"}, nil)
		m := newMgr(t, Nftables, "app", r)
		if err := m.RemoveRule(context.Background(), "ssh"); err == nil {
			t.Fatal("a real list failure must propagate, not read as 'rule already absent'")
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
	t.Run("no table → wrapped os.ErrNotExist", func(t *testing.T) {
		r := &recordingRunner{}
		r.push(exec.Result{ExitCode: 1, Stderr: "Error: No such file or directory"}, nil)
		m := newMgr(t, Nftables, "app", r)
		rules, err := m.List(context.Background())
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("List(no table) err = %v, want wrapped os.ErrNotExist", err)
		}
		if rules != nil {
			t.Errorf("List(no table) rules = %v, want nil", rules)
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

// TestFirewalld_ApplyRule_CleansUpOnlyTheXMLItCreated pins the failure
// atomicity of ApplyRule, and its deliberate asymmetry.
//
// The service XML is written before the reload/add-service/reload sequence, so
// a failure in any of those used to leave the file on disk. That matters
// because firewalld PARSES every file in /etc/firewalld/services on the next
// reload by anything at all: an Apply the caller was told had failed would
// quietly become a real, loadable service definition.
//
// But ApplyRule also UPDATES an existing rule, overwriting a service that may
// still be enabled in the zone. Deleting on failure there would destroy a
// working definition that nothing asked us to touch, turning a failed update
// into an outage. So cleanup is create-only: remove when this Apply brought the
// file into existence, leave it when it was already there — and when the
// existence probe itself fails, leave it, because "we don't know" must never
// resolve to "delete".
func TestFirewalld_ApplyRule_CleansUpOnlyTheXMLItCreated(t *testing.T) {
	const wantPath = "/etc/firewalld/services/app-r.xml"
	rule := Rule{ID: "r", Allow: true, Protocol: ProtocolTCP, Port: 1}

	// failAt scripts the zone lookup plus n successful firewall-cmd calls, then
	// one failing call — so each post-write step can be made to fail in turn.
	failAt := func(r *recordingRunner, okCalls int) {
		r.pushOut("public\n") // --get-default-zone
		for i := 0; i < okCalls; i++ {
			r.pushOut("")
		}
		r.push(exec.Result{ExitCode: 1}, nil)
	}

	steps := map[string]int{
		"reload fails":             0,
		"add-service fails":        1,
		"post-enable reload fails": 2,
	}

	for name, okCalls := range steps {
		t.Run("created, "+name+" → xml removed", func(t *testing.T) {
			swapFirewalldSeams(t)
			var removed []string
			useFS(&fakeFS{ // nothing on disk → the exclusive create succeeds, we own it
				removeFn: func(p string) error { removed = append(removed, p); return nil },
			})
			r := &recordingRunner{}
			failAt(r, okCalls)
			m := newMgr(t, Firewalld, "app", r)
			if err := m.ApplyRule(context.Background(), rule); err == nil {
				t.Fatal("the failing firewall-cmd step must propagate")
			}
			if len(removed) != 1 || removed[0] != wantPath {
				t.Errorf("removed = %v, want the just-created %q cleaned up", removed, wantPath)
			}
		})

		t.Run("pre-existing, "+name+" → xml kept", func(t *testing.T) {
			swapFirewalldSeams(t)
			var removed []string
			useFS(&fakeFS{
				// Already on disk → the exclusive create reports fs.ErrExists and the
				// backend falls back to an overwrite it does NOT own.
				present:  map[string]bool{wantPath: true},
				removeFn: func(p string) error { removed = append(removed, p); return nil },
			})
			r := &recordingRunner{}
			failAt(r, okCalls)
			m := newMgr(t, Firewalld, "app", r)
			if err := m.ApplyRule(context.Background(), rule); err == nil {
				t.Fatal("the failing firewall-cmd step must propagate")
			}
			if len(removed) != 0 {
				t.Errorf("removed = %v; a failed UPDATE must not delete the pre-existing service definition, which may still be enabled in the zone", removed)
			}
		})
	}

	// The race the create-exclusive design exists to close. Under the old
	// Exists-then-WriteFile shape, a definition landing in the gap between the
	// probe (which said "absent") and the write would be overwritten AND then
	// deleted on failure, destroying a service someone else owns and may still
	// have enabled in the zone. Here the foreign file is present by the time the
	// write happens, so the exclusive create reports it and ownership is declined.
	t.Run("foreign file appears before the write → left untouched on failure", func(t *testing.T) {
		swapFirewalldSeams(t)
		var removed []string
		ff := &fakeFS{removeFn: func(p string) error { removed = append(removed, p); return nil }}
		// Plant it exactly as a competing writer would: present before our write,
		// with no cooperation from us.
		ff.present = map[string]bool{wantPath: true}
		useFS(ff)
		r := &recordingRunner{}
		failAt(r, 0)
		m := newMgr(t, Firewalld, "app", r)
		if err := m.ApplyRule(context.Background(), rule); err == nil {
			t.Fatal("the failing firewall-cmd step must propagate")
		}
		if len(removed) != 0 {
			t.Errorf("removed = %v; a file this Apply did not create must survive the failure — deleting it would destroy a definition another owner may still have enabled", removed)
		}
	})

	// Positive control: a fully successful Apply keeps its XML.
	t.Run("success keeps the xml", func(t *testing.T) {
		swapFirewalldSeams(t)
		var removed []string
		useFS(&fakeFS{removeFn: func(p string) error { removed = append(removed, p); return nil }})
		r := &recordingRunner{}
		r.pushOut("public\n")
		r.pushOut("")
		r.pushOut("")
		r.pushOut("")
		m := newMgr(t, Firewalld, "app", r)
		if err := m.ApplyRule(context.Background(), rule); err != nil {
			t.Fatal(err)
		}
		if len(removed) != 0 {
			t.Errorf("removed = %v, want the XML kept after a successful Apply", removed)
		}
	})

	// The cleanup is best-effort: when the removal ALSO fails the file is still
	// there, and the error must say so rather than implying a clean rollback.
	t.Run("cleanup failure is reported", func(t *testing.T) {
		swapFirewalldSeams(t)
		useFS(&fakeFS{ // fresh create → owned, so cleanup is attempted
			removeFn: func(string) error { return errors.New("read-only fs") },
		})
		r := &recordingRunner{}
		failAt(r, 0)
		m := newMgr(t, Firewalld, "app", r)
		err := m.ApplyRule(context.Background(), rule)
		if err == nil {
			t.Fatal("the failing firewall-cmd step must propagate")
		}
		if !strings.Contains(err.Error(), wantPath) {
			t.Errorf("err = %v, want it to name the %q left behind", err, wantPath)
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
		// An inactive ufw exits 0 with "Status: inactive" — the firewall IS
		// installed, it just holds no rules, so List is legitimately empty.
		r.pushOut("Status: inactive\n")
		m := newMgr(t, UFW, "app", r)
		rules, err := m.List(context.Background())
		if err != nil || len(rules) != 0 {
			t.Errorf("List = (%v,%v), want empty", rules, err)
		}
	})
	t.Run("can't run ufw propagates", func(t *testing.T) {
		r := &recordingRunner{}
		// A non-zero exit (ufw absent, escalation denied) is a genuine
		// can't-determine-state failure and must NOT be read as "zero rules".
		r.push(exec.Result{ExitCode: 1}, nil)
		m := newMgr(t, UFW, "app", r)
		if _, err := m.List(context.Background()); err == nil {
			t.Fatal("a failure to run ufw status must propagate, not read as 'no managed rules'")
		}
	})
}
