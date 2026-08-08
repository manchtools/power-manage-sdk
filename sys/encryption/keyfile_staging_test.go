package encryption

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
)

// withKeyFileDir points the key-file staging root at dir for one test.
func withKeyFileDir(t *testing.T, dir string) {
	t.Helper()
	orig := keyFileDir
	keyFileDir = dir
	t.Cleanup(func() { keyFileDir = orig })
}

// assertNeverStagedIn asserts the intent behind the staging directory: whatever
// the package does when a hostile directory is pre-created at the configured
// path, the plaintext key file must never land in it. Two outcomes are
// acceptable — fail closed, or write into a REAL directory this process owns at
// mode exactly 0700, which is the only shape in which another local uid on a
// world-writable tmpfs cannot rename or replace the entries inside it.
func assertNeverStagedIn(t *testing.T, path string, err error, hostileDir string) {
	t.Helper()
	if err != nil {
		return // fail-closed is the other acceptable outcome
	}
	t.Cleanup(func() { cleanupKeyFile(path) })

	dir := filepath.Dir(path)
	info, statErr := os.Lstat(dir)
	if statErr != nil {
		t.Fatalf("staging directory %s of key file %s: %v", dir, path, statErr)
	}
	if hostileInfo, hErr := os.Lstat(hostileDir); hErr == nil && os.SameFile(info, hostileInfo) {
		t.Fatalf("key file %s was staged in the attacker-created directory %s: owning the directory lets the attacker replace the key file cryptsetup re-resolves", path, hostileDir)
	}
	if !info.Mode().IsDir() {
		t.Fatalf("key file %s was staged through %s, which is not a real directory (mode %s)", path, dir, info.Mode())
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("staging directory %s mode = %o, want exactly 0700; a wider mode lets another local uid replace the staged key file", dir, perm)
	}
	uid, ok := ownerUID(info)
	if !ok {
		t.Fatalf("staging directory %s exposes no owning uid; ownership must be checkable or the write must fail closed", dir)
	}
	if uid != os.Geteuid() {
		t.Fatalf("staging directory %s is owned by uid %d, want this process's euid %d", dir, uid, os.Geteuid())
	}
}

// TestWriteKeyFile_RefusesPreCreatedStagingDirectory is F1. os.MkdirAll returns
// nil for a directory that already exists WITHOUT checking its owner or mode,
// and /dev/shm is world-writable, so any local uid that wins the once-per-boot
// race owns the directory the root agent then writes LUKS key files into.
func TestWriteKeyFile_RefusesPreCreatedStagingDirectory(t *testing.T) {
	t.Run("world-writable directory pre-created at the configured path", func(t *testing.T) {
		root := t.TempDir()
		hostile := filepath.Join(root, "pm-luks")
		if err := os.Mkdir(hostile, 0o700); err != nil {
			t.Fatal(err)
		}
		// Chmod separately: os.Mkdir's mode is masked by umask.
		if err := os.Chmod(hostile, 0o777); err != nil {
			t.Fatal(err)
		}
		withKeyFileDir(t, hostile)

		staged, err := writeKeyFile(mustSecret(t, "the-passphrase"))
		assertNeverStagedIn(t, staged.path, err, hostile)
	})

	t.Run("symlink planted at the configured path", func(t *testing.T) {
		root := t.TempDir()
		attacker := filepath.Join(root, "attacker")
		if err := os.Mkdir(attacker, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(root, "pm-luks")
		if err := os.Symlink(attacker, link); err != nil {
			t.Fatal(err)
		}
		withKeyFileDir(t, link)

		staged, err := writeKeyFile(mustSecret(t, "the-passphrase"))
		assertNeverStagedIn(t, staged.path, err, attacker)
	})

	t.Run("directory owned by another uid", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("chown to a foreign uid needs root; the ownership predicate is unit-tested in TestVerifyStagingDir_RefusesForeignOwner")
		}
		root := t.TempDir()
		hostile := filepath.Join(root, "pm-luks")
		if err := os.Mkdir(hostile, 0o700); err != nil {
			t.Fatal(err)
		}
		const nobodyUID, nobodyGID = 65534, 65534
		if err := os.Chown(hostile, nobodyUID, nobodyGID); err != nil {
			t.Fatal(err)
		}
		withKeyFileDir(t, hostile)

		staged, err := writeKeyFile(mustSecret(t, "the-passphrase"))
		assertNeverStagedIn(t, staged.path, err, hostile)
	})
}

// TestVerifyStagingDir_RefusesForeignOwner covers the ownership half of the
// staging check without root: the directory is real and 0700, but the process
// euid it must match is redirected, which is what a directory pre-created by
// another local uid looks like from the daemon's side.
func TestVerifyStagingDir_RefusesForeignOwner(t *testing.T) {
	defer swapKeyFileSeams(t)()
	dir := t.TempDir()
	// t.TempDir yields 0777&^umask; the real os.MkdirTemp yields 0700.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := verifyStagingDir(dir); err != nil {
		t.Fatalf("positive control: a self-owned 0700 directory must be accepted, got %v", err)
	}

	geteuid = func() int { return os.Geteuid() + 1 }
	err := verifyStagingDir(dir)
	if !errors.Is(err, ErrKeyFileStaging) {
		t.Fatalf("verifyStagingDir(foreign owner) = %v, want ErrKeyFileStaging", err)
	}
}

func TestVerifyStagingParent_RefusesForeignOwner(t *testing.T) {
	defer swapKeyFileSeams(t)()
	dir := t.TempDir()
	lstatFile = func(path string) (os.FileInfo, error) {
		info, err := os.Lstat(path)
		return ownerOverride{FileInfo: info, uid: uint32(os.Geteuid() + 1)}, err
	}
	if err := verifyStagingParent(dir); !errors.Is(err, ErrKeyFileStaging) {
		t.Fatalf("verifyStagingParent(foreign owner) = %v, want ErrKeyFileStaging", err)
	}
}

type ownerOverride struct {
	os.FileInfo
	uid uint32
}

func (i ownerOverride) Sys() any { return &syscall.Stat_t{Uid: i.uid} }

// TestVerifyStagingDir_RefusesWidenedModeAndNonDirectories pins the rest of the
// predicate: only a real directory at mode exactly 0700 may hold key material.
func TestVerifyStagingDir_RefusesWidenedModeAndNonDirectories(t *testing.T) {
	root := t.TempDir()

	wide := filepath.Join(root, "wide")
	if err := os.Mkdir(wide, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wide, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := verifyStagingDir(wide); !errors.Is(err, ErrKeyFileStaging) {
		t.Errorf("verifyStagingDir(0770) = %v, want ErrKeyFileStaging", err)
	}

	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := verifyStagingDir(link); !errors.Is(err, ErrKeyFileStaging) {
		t.Errorf("verifyStagingDir(symlink) = %v, want ErrKeyFileStaging (Lstat must not follow it)", err)
	}

	if err := verifyStagingDir(filepath.Join(root, "absent")); !errors.Is(err, ErrKeyFileStaging) {
		t.Errorf("verifyStagingDir(missing) = %v, want ErrKeyFileStaging", err)
	}
}

// TestVerifyStagingParent_RequiresStickyWhenWorldWritable pins why /dev/shm is
// usable at all: it is mode 1777, so another local uid cannot rename or delete
// the private directory created inside it. A world-writable parent without the
// sticky bit gives that power away and must be refused.
func TestVerifyStagingParent_RequiresStickyWhenWorldWritable(t *testing.T) {
	root := t.TempDir()

	open := filepath.Join(root, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := verifyStagingParent(open); !errors.Is(err, ErrKeyFileStaging) {
		t.Errorf("verifyStagingParent(0777, no sticky) = %v, want ErrKeyFileStaging", err)
	}

	// Group-writable is the same hazard for anyone in that group.
	groupOpen := filepath.Join(root, "group-open")
	if err := os.Mkdir(groupOpen, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(groupOpen, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := verifyStagingParent(groupOpen); !errors.Is(err, ErrKeyFileStaging) {
		t.Errorf("verifyStagingParent(0770, no sticky) = %v, want ErrKeyFileStaging", err)
	}

	sticky := filepath.Join(root, "sticky")
	if err := os.Mkdir(sticky, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sticky, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := verifyStagingParent(sticky); err != nil {
		t.Errorf("positive control: verifyStagingParent(1777) = %v, want nil (this is /dev/shm)", err)
	}
}

// TestAddKey_DetectsKeyFileSwapBeforeExec is the second half of F1: writeKeyFile
// hands cryptsetup a PATH, not an open descriptor, so anyone able to replace
// the entry between staging and exec chooses the passphrase that gets enrolled.
// AddKey stages two key files, so the swap is planted while the second is being
// created — after the first has already been handed back.
func TestAddKey_DetectsKeyFileSwapBeforeExec(t *testing.T) {
	defer swapKeyFileSeams(t)()

	const attackerKey = "attacker-chosen-key"
	calls := 0
	first := ""
	createKeyFile = func(dir string) (keyFileHandle, error) {
		calls++
		if calls == 2 && first != "" {
			swap := filepath.Join(dir, "swapped")
			if err := os.WriteFile(swap, []byte(attackerKey), 0o600); err != nil {
				t.Fatalf("plant swap file: %v", err)
			}
			// A rename over the path is exactly what owning the directory buys.
			if err := os.Rename(swap, first); err != nil {
				t.Fatalf("swap staged key file: %v", err)
			}
		}
		f, err := os.CreateTemp(dir, "key-*")
		if err != nil {
			return nil, err
		}
		if calls == 1 {
			first = f.Name()
		}
		return f, nil
	}

	r := &recordingRunner{}
	err := mgr(t, r).AddKey(context.Background(), "/dev/sda2",
		mustSecret(t, "oldpass"), mustSecret(t, "newpass"), AddKeyOptions{})
	if err == nil {
		t.Error("AddKey accepted a key file replaced after staging; cryptsetup would enroll the attacker's passphrase")
	}
	if n := len(r.calls); n != 0 {
		t.Errorf("AddKey ran cryptsetup %d time(s) after a key-file swap; the swap must be detected BEFORE exec", n)
	}
	for _, c := range r.calls {
		for _, content := range c.keyFiles {
			if content == attackerKey {
				t.Error("cryptsetup was handed the attacker's key file content")
			}
		}
	}
}

// TestEverySecretMethodRefusesHostileStagingDir is the self-discovering guard:
// for EVERY Manager method that takes an exec.Secret, a world-writable staging
// directory pre-created at the configured path must stop cryptsetup running at
// all. lsblk is read-only and unprivileged, so only cryptsetup invocations are
// counted.
func TestEverySecretMethodRefusesHostileStagingDir(t *testing.T) {
	root := t.TempDir()
	hostile := filepath.Join(root, "pm-luks")
	if err := os.Mkdir(hostile, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(hostile, 0o777); err != nil {
		t.Fatal(err)
	}
	withKeyFileDir(t, hostile)

	mt := reflect.TypeOf((*Manager)(nil)).Elem()
	ctxType := reflect.TypeOf((*context.Context)(nil)).Elem()
	secretType := reflect.TypeOf(exec.Secret{})
	checked := 0

	for i := 0; i < mt.NumMethod(); i++ {
		name := mt.Method(i).Name
		ft := reflect.ValueOf(mgr(t, &recordingRunner{})).MethodByName(name).Type()
		takesSecret := false
		for p := 0; p < ft.NumIn(); p++ {
			if ft.In(p) == secretType {
				takesSecret = true
			}
		}
		if !takesSecret {
			continue
		}
		r := &recordingRunner{}
		// A single LUKS volume so DetectVolumeByKey reaches the key-file stage.
		r.push(exec.Result{Stdout: `{"blockdevices":[{"name":"sda2","type":"part","fstype":"crypto_LUKS"}]}`}, nil)
		fn := reflect.ValueOf(mgr(t, r)).MethodByName(name)
		args := make([]reflect.Value, ft.NumIn())
		for p := 0; p < ft.NumIn(); p++ {
			pt := ft.In(p)
			switch {
			case pt == ctxType:
				args[p] = reflect.ValueOf(context.Background())
			case pt.Kind() == reflect.String:
				args[p] = reflect.ValueOf("/dev/sda2")
			case pt == secretType:
				args[p] = reflect.ValueOf(mustSecret(t, "a-passphrase"))
			default:
				args[p] = reflect.Zero(pt)
			}
		}
		out := fn.Call(args)
		if len(out) == 0 {
			t.Errorf("%s exposes no error result", name)
		} else if err, ok := out[len(out)-1].Interface().(error); !ok || err == nil {
			t.Errorf("%s returned no error with an attacker-owned staging parent", name)
		}
		for _, c := range r.calls {
			if strings.HasPrefix(c.cmd.Name, "cryptsetup") {
				t.Errorf("%s ran %s with a key file staged in an attacker-owned directory", name, c.cmd.Name)
			}
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("matches-zero guard: no Secret-taking Manager methods exercised")
	}
}
