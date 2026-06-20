package adversary

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/sys/desktop"
	"github.com/manchtools/power-manage-sdk/sys/dns"
	"github.com/manchtools/power-manage-sdk/sys/encryption"
	sdkexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
	"github.com/manchtools/power-manage-sdk/sys/firewall"
	"github.com/manchtools/power-manage-sdk/sys/fs"
	"github.com/manchtools/power-manage-sdk/sys/notify"
	"github.com/manchtools/power-manage-sdk/sys/osquery"
	"github.com/manchtools/power-manage-sdk/sys/reboot"
	"github.com/manchtools/power-manage-sdk/sys/remote"
	"github.com/manchtools/power-manage-sdk/sys/user"
)

type oracle int

const (
	mustReject oracle = 1 << iota
	noPrivilegedExec
	noPrivilegedMutation
	noNetwork
	noDiskMutation
	noSecretArgv
)

type programStep struct {
	name   string
	oracle oracle
	run    func(*testing.T, *attackEnv) observation
}

type attackProgram struct {
	name  string
	steps []programStep
}

type observation struct {
	err              error
	commands         []sdkexec.Command
	networkRequests  int
	diskPath         string
	secretNeedles    []string
	additionalDetail string
}

type attackEnv struct {
	ctx context.Context
}

// TestAdversarialAgentSecurityMachine is a cross-SDK adversarial finite suite:
// each program is a short attacker playbook that chains remote input into local
// privileged SDK surfaces, while a common oracle checks global safety properties
// (reject before privileged execution/mutation, no network/disk side effects,
// no secrets in argv). Package-local tests still pin individual bugs; this suite
// is the higher-level attacker model that should stay red until the hardening is
// implemented.
func TestAdversarialAgentSecurityMachine(t *testing.T) {
	programs := []attackProgram{
		remoteToRootPersistenceProgram(),
		controlPlaneLocalExfiltrationProgram(t),
		accountAndDesktopPersistenceProgram(),
		networkAndFirewallTakeoverProgram(),
		rebootAndNotificationDoSProgram(),
		encryptionSecretHygieneProgram(),
	}

	for _, program := range programs {
		t.Run(program.name, func(t *testing.T) {
			env := &attackEnv{ctx: context.Background()}
			for _, step := range program.steps {
				t.Run(step.name, func(t *testing.T) {
					obs := step.run(t, env)
					checkOracle(t, step, obs)
				})
			}
		})
	}
}

func checkOracle(t *testing.T, step programStep, obs observation) {
	t.Helper()
	if step.oracle&mustReject != 0 && obs.err == nil {
		t.Errorf("attacker step was accepted; want rejection")
	}
	if step.oracle&mustReject == 0 && obs.err != nil {
		t.Errorf("baseline step failed unexpectedly: %v", obs.err)
	}
	if step.oracle&noPrivilegedExec != 0 {
		if calls := privilegedCalls(obs.commands); len(calls) != 0 {
			t.Errorf("attacker step reached privileged execution: %+v", calls)
		}
	}
	if step.oracle&noPrivilegedMutation != 0 {
		if calls := privilegedMutations(obs.commands); len(calls) != 0 {
			t.Errorf("attacker step reached privileged mutation: %+v", calls)
		}
	}
	if step.oracle&noNetwork != 0 && obs.networkRequests != 0 {
		t.Errorf("attacker step performed %d network request(s)", obs.networkRequests)
	}
	if step.oracle&noDiskMutation != 0 && obs.diskPath != "" {
		if _, err := os.Stat(obs.diskPath); !os.IsNotExist(err) {
			t.Errorf("attacker step mutated disk path %q (stat err=%v)", obs.diskPath, err)
		}
	}
	if step.oracle&noSecretArgv != 0 {
		if leaks := argvLeaks(obs.commands, obs.secretNeedles); len(leaks) != 0 {
			t.Errorf("secret material leaked into argv: %v", leaks)
		}
	}
	if obs.additionalDetail != "" {
		t.Log(obs.additionalDetail)
	}
}

func remoteToRootPersistenceProgram() attackProgram {
	return attackProgram{
		name: "remote payload to root persistence",
		steps: []programStep{
			{
				name:   "pinned payload can be fetched to a non-system staging path",
				oracle: noSecretArgv,
				run: func(t *testing.T, env *attackEnv) observation {
					payload := []byte("benign\n")
					origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(payload) }))
					t.Cleanup(origin.Close)
					sum := sha256.Sum256(payload)
					src, err := remote.NewHTTP(remote.HTTPConfig{URL: origin.URL + "/payload", ChecksumSHA256: hex.EncodeToString(sum[:])})
					if err != nil {
						return observation{err: err}
					}
					dest := filepath.Join(t.TempDir(), "payload")
					_, err = src.Fetch(env.ctx, dest)
					return observation{err: err, diskPath: ""}
				},
			},
			{
				name:   "cross-host redirect cannot choose the downloaded bytes",
				oracle: mustReject | noNetwork | noDiskMutation,
				run: func(t *testing.T, env *attackEnv) observation {
					var targetHits atomic.Int32
					target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						targetHits.Add(1)
						_, _ = w.Write([]byte("attacker payload\n"))
					}))
					t.Cleanup(target.Close)
					redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						http.Redirect(w, r, target.URL+"/payload", http.StatusFound)
					}))
					t.Cleanup(redirector.Close)
					dest := filepath.Join(t.TempDir(), "redirected")
					src, err := remote.NewHTTP(remote.HTTPConfig{URL: redirector.URL + "/start"})
					if err == nil {
						_, err = src.Fetch(env.ctx, dest)
					}
					return observation{err: err, networkRequests: int(targetHits.Load()), diskPath: dest}
				},
			},
			{
				name:   "downloaded helper cannot be made setuid root",
				oracle: mustReject | noPrivilegedMutation,
				run: func(t *testing.T, env *attackEnv) observation {
					r := exectest.New(sdkexec.Sudo)
					m, err := fs.New(r)
					if err == nil {
						err = m.SetMode(env.ctx, "/etc/pm-downloaded-helper", os.FileMode(0o755)|os.ModeSetuid)
					}
					return observation{err: err, commands: r.Calls()}
				},
			},
		},
	}
}

func controlPlaneLocalExfiltrationProgram(t *testing.T) attackProgram {
	return attackProgram{
		name: "control plane command to local exfiltration",
		steps: []programStep{
			{
				name:   "ordinary inventory query can run privileged osquery",
				oracle: noSecretArgv,
				run: func(t *testing.T, env *attackEnv) observation {
					installFakeTool(t, "osqueryi")
					r := exectest.New(sdkexec.Direct)
					r.Push(sdkexec.Result{Stdout: `[{"name":"linux"}]`}, nil)
					q, err := osquery.New(r)
					if err == nil {
						res, qerr := q.Query(env.ctx, osqueryPayloadTable("os_version"))
						if qerr != nil {
							err = qerr
						} else if !res.GetSuccess() {
							err = errors.New(res.GetError())
						}
					}
					return observation{err: err, commands: r.Calls()}
				},
			},
			{
				name:   "raw SQL cannot read credential tables",
				oracle: mustReject | noPrivilegedExec,
				run: func(t *testing.T, env *attackEnv) observation {
					installFakeTool(t, "osqueryi")
					r := exectest.New(sdkexec.Direct)
					r.Push(sdkexec.Result{Stdout: `[{"username":"root","hash":"$y$j9T$secret"}]`}, nil)
					q, err := osquery.New(r)
					if err == nil {
						res, qerr := q.Query(env.ctx, osqueryPayloadRaw("WITH stolen AS (SELECT * FROM shadow) SELECT * FROM stolen"))
						if qerr != nil {
							err = qerr
						} else if !res.GetSuccess() {
							err = errors.New(res.GetError())
						}
					}
					return observation{err: err, commands: r.Calls()}
				},
			},
		},
	}
}

func accountAndDesktopPersistenceProgram() attackProgram {
	return attackProgram{
		name: "account and desktop persistence",
		steps: []programStep{
			{
				name:   "system account with nologin can be created",
				oracle: noSecretArgv,
				run: func(t *testing.T, env *attackEnv) observation {
					r := exectest.New(sdkexec.Direct)
					m, err := user.New(user.ShadowUtils, r)
					if err == nil {
						err = m.Create(env.ctx, "svc", user.CreateOptions{System: true})
					}
					return observation{err: err, commands: r.Calls()}
				},
			},
			{
				name:   "new account cannot persist with tmp shell and root home",
				oracle: mustReject | noPrivilegedMutation,
				run: func(t *testing.T, env *attackEnv) observation {
					r := exectest.New(sdkexec.Direct)
					m, err := user.New(user.ShadowUtils, r)
					if err == nil {
						err = m.Create(env.ctx, "deploy", user.CreateOptions{HomeDir: "/", Shell: "/tmp/pwnsh", CreateHome: true})
					}
					return observation{err: err, commands: r.Calls()}
				},
			},
			{
				name:   "desktop run-as cannot inherit loader injection",
				oracle: mustReject,
				run: func(t *testing.T, env *attackEnv) observation {
					r := exectest.New(sdkexec.Direct)
					m, err := desktop.New(r)
					if err == nil {
						_, err = m.RunAsCommand(env.ctx, desktop.Session{Username: "alice", UID: 1000, GID: 1000, Home: "/home/alice", RuntimeDir: "/run/user/1000"}, desktop.RunAsOptions{ExtraEnv: []string{"LD_PRELOAD=/tmp/evil.so"}}, "/usr/bin/true")
					}
					return observation{err: err, commands: r.Calls()}
				},
			},
		},
	}
}

func networkAndFirewallTakeoverProgram() attackProgram {
	return attackProgram{
		name: "network and firewall takeover",
		steps: []programStep{
			{
				name:   "NetworkManager connection name from host output is revalidated",
				oracle: mustReject | noPrivilegedMutation,
				run: func(t *testing.T, env *attackEnv) observation {
					r := exectest.New(sdkexec.Direct)
					r.Push(sdkexec.Result{Stdout: "-evil\n"}, nil)
					m, err := dns.New(dns.NetworkManager, r)
					if err == nil {
						err = m.Apply(env.ctx, dns.Config{Interface: "eth0", Nameservers: []string{"10.0.0.53"}})
					}
					return observation{err: err, commands: r.Calls()}
				},
			},
			{
				name:   "DNS cannot be poisoned with unspecified resolver",
				oracle: mustReject | noPrivilegedMutation,
				run: func(t *testing.T, env *attackEnv) observation {
					r := exectest.New(sdkexec.Direct)
					r.Push(sdkexec.Result{Stdout: "Corp WiFi\n"}, nil)
					m, err := dns.New(dns.NetworkManager, r)
					if err == nil {
						err = m.Apply(env.ctx, dns.Config{Interface: "wlan0", Nameservers: []string{"0.0.0.0"}})
					}
					return observation{err: err, commands: r.Calls()}
				},
			},
			{
				name:   "firewall cannot install allow-all ingress rule",
				oracle: mustReject | noPrivilegedMutation,
				run: func(t *testing.T, env *attackEnv) observation {
					r := exectest.New(sdkexec.Direct)
					m, err := firewall.New(firewall.Nftables, "agent", r)
					if err == nil {
						err = m.ApplyRule(env.ctx, firewall.Rule{ID: "allow_all", Allow: true})
					}
					return observation{err: err, commands: r.Calls()}
				},
			},
		},
	}
}

func rebootAndNotificationDoSProgram() attackProgram {
	return attackProgram{
		name: "reboot and notification denial-of-service",
		steps: []programStep{
			{
				name:   "scheduled reboot must keep a grace window",
				oracle: mustReject | noPrivilegedMutation,
				run: func(t *testing.T, env *attackEnv) observation {
					r := exectest.New(sdkexec.Sudo)
					m, err := reboot.New(r)
					if err == nil {
						err = m.Schedule(env.ctx, reboot.ScheduleOptions{Delay: "now", Message: "maintenance"})
					}
					return observation{err: err, commands: r.Calls()}
				},
			},
			{
				name:   "terminal-control notification cannot be broadcast",
				oracle: mustReject | noPrivilegedMutation,
				run: func(t *testing.T, env *attackEnv) observation {
					r := exectest.New(sdkexec.Sudo)
					m, err := notify.New(r)
					if err == nil {
						err = m.NotifyAll(env.ctx, "Maintenance", "reboot \x1b[2Jnow")
					}
					return observation{err: err, commands: r.Calls()}
				},
			},
		},
	}
}

func encryptionSecretHygieneProgram() attackProgram {
	return attackProgram{
		name: "encryption secret hygiene",
		steps: []programStep{
			{
				name:   "LUKS key rotation keeps passphrases out of argv",
				oracle: noSecretArgv,
				run: func(t *testing.T, env *attackEnv) observation {
					r := exectest.New(sdkexec.Direct)
					m, err := encryption.New(encryption.LUKS, r)
					oldKey := mustSecret(t, "correct horse battery staple")
					newKey := mustSecret(t, "new secret passphrase")
					if err == nil {
						err = m.AddKey(env.ctx, "/dev/sda1", oldKey, newKey, encryption.AddKeyOptions{})
					}
					return observation{err: err, commands: r.Calls(), secretNeedles: []string{oldKey.Reveal(), newKey.Reveal()}}
				},
			},
			{
				name:   "LUKS mutator rejects traversal-shaped device before key handling",
				oracle: mustReject | noPrivilegedExec,
				run: func(t *testing.T, env *attackEnv) observation {
					r := exectest.New(sdkexec.Direct)
					m, err := encryption.New(encryption.LUKS, r)
					if err == nil {
						err = m.RemoveKey(env.ctx, "/dev/disk/by-id/../../shadow", mustSecret(t, "current secret"))
					}
					return observation{err: err, commands: r.Calls()}
				},
			},
		},
	}
}

func osqueryPayloadTable(table string) *pb.OSQuery {
	return &pb.OSQuery{QueryId: "adversary", Table: table}
}

func osqueryPayloadRaw(sql string) *pb.OSQuery {
	return &pb.OSQuery{QueryId: "adversary", RawSql: sql}
}

func installFakeTool(t *testing.T, name string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func mustSecret(t *testing.T, value string) sdkexec.Secret {
	t.Helper()
	secret, err := sdkexec.NewSecret(value)
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	return secret
}

func privilegedCalls(commands []sdkexec.Command) []string {
	var out []string
	for _, c := range commands {
		if c.Escalate {
			out = append(out, commandString(c))
		}
	}
	return out
}

func privilegedMutations(commands []sdkexec.Command) []string {
	var out []string
	for _, c := range commands {
		if isPrivilegedMutation(c) {
			out = append(out, commandString(c))
		}
	}
	return out
}

func isPrivilegedMutation(c sdkexec.Command) bool {
	if !c.Escalate {
		return false
	}
	switch c.Name {
	case "nft":
		return containsArg(c.Args, "-f")
	case "nmcli":
		return len(c.Args) >= 2 && c.Args[0] == "connection" && (c.Args[1] == "modify" || c.Args[1] == "up")
	case "resolvectl", "systemctl", "shutdown", "wall", "useradd", "usermod", "userdel", "chpasswd", "chage", "chown", "chmod", "cp", "rm", "mkdir", "sh", "ufw", "firewall-cmd", "cryptsetup":
		return true
	default:
		return false
	}
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func argvLeaks(commands []sdkexec.Command, needles []string) []string {
	if len(needles) == 0 {
		return nil
	}
	var leaks []string
	for _, c := range commands {
		argv := commandString(c)
		for _, needle := range needles {
			if needle != "" && strings.Contains(argv, needle) {
				leaks = append(leaks, fmt.Sprintf("%q in %s", needle, argv))
			}
		}
	}
	return leaks
}

func commandString(c sdkexec.Command) string {
	return strings.TrimSpace(c.Name + " " + strings.Join(c.Args, " "))
}
