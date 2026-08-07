package encryption

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"
)

var errIO = errors.New("injected I/O failure")

// fakeKeyFile injects a failure into one of the writeKeyFile file ops.
type fakeKeyFile struct {
	name      string
	failChmod bool
	failWrite bool
	failClose bool
}

func (f *fakeKeyFile) Name() string { return f.name }
func (f *fakeKeyFile) Chmod(os.FileMode) error {
	if f.failChmod {
		return errIO
	}
	return nil
}
func (f *fakeKeyFile) WriteString(string) (int, error) {
	if f.failWrite {
		return 0, errIO
	}
	return 0, nil
}
func (f *fakeKeyFile) Close() error {
	if f.failClose {
		return errIO
	}
	return nil
}

// resetKeyFileStaging drops the cached per-process staging directory so a test
// neither inherits nor leaves behind a directory created under different seams.
func resetKeyFileStaging() {
	stagingMu.Lock()
	defer stagingMu.Unlock()
	stagingDir, stagingRoot = "", ""
}

// swapKeyFileSeams installs fault-injecting key-file seams and returns a restore.
func swapKeyFileSeams(t *testing.T) func() {
	t.Helper()
	mt, ls, ge, c, rm, o := mkdirTemp, lstatFile, geteuid, createKeyFile, removeFile, openKeyFile
	resetKeyFileStaging()
	return func() {
		mkdirTemp, lstatFile, geteuid, createKeyFile, removeFile, openKeyFile = mt, ls, ge, c, rm, o
		resetKeyFileStaging()
	}
}

// stagingDirSeam points mkdirTemp at a real private (0700, self-owned)
// directory so a fault test reaches the file operations it is exercising
// instead of stopping at the staging-directory check.
func stagingDirSeam(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// t.TempDir's numbered subdirectory is created 0777&^umask (0755 by
	// default), which the staging check correctly refuses; chmod it to the mode
	// the real os.MkdirTemp would produce.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	mkdirTemp = func(string, string) (string, error) { return dir, nil }
	return dir
}

func TestWriteKeyFile_FaultPaths(t *testing.T) {
	t.Run("staging directory creation fails", func(t *testing.T) {
		defer swapKeyFileSeams(t)()
		mkdirTemp = func(string, string) (string, error) { return "", errIO }
		if _, err := writeKeyFile(mustSecret(t, "x")); err == nil {
			t.Error("writeKeyFile ignored a staging-directory failure")
		}
	})
	t.Run("create fails", func(t *testing.T) {
		defer swapKeyFileSeams(t)()
		stagingDirSeam(t)
		createKeyFile = func(string) (keyFileHandle, error) { return nil, errIO }
		if _, err := writeKeyFile(mustSecret(t, "x")); err == nil {
			t.Error("writeKeyFile ignored a create failure")
		}
	})

	removed := func(t *testing.T) *bool {
		t.Helper()
		var b bool
		removeFile = func(string) error { b = true; return nil }
		return &b
	}
	for _, tc := range []struct {
		name string
		set  func(*fakeKeyFile)
	}{
		{"chmod fails", func(f *fakeKeyFile) { f.failChmod = true }},
		{"write fails", func(f *fakeKeyFile) { f.failWrite = true }},
		{"close fails", func(f *fakeKeyFile) { f.failClose = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer swapKeyFileSeams(t)()
			stagingDirSeam(t)
			fk := &fakeKeyFile{name: "/dev/shm/pm-luks/key-xxx"}
			tc.set(fk)
			createKeyFile = func(string) (keyFileHandle, error) { return fk, nil }
			rm := removed(t)
			if _, err := writeKeyFile(mustSecret(t, "x")); err == nil {
				t.Errorf("writeKeyFile ignored a %s", tc.name)
			}
			// chmod/write failures clean up the partial file; close-failure too.
			if !*rm {
				t.Errorf("%s: partial key file was not removed", tc.name)
			}
		})
	}
}

// When the key-file cleanup itself fails after a write failure, the error must
// surface that plaintext key material may remain on /dev/shm — a dropped
// removeFile error would hide a leaked LUKS key file.
func TestWriteKeyFile_CleanupFailureSurfacesResidue(t *testing.T) {
	defer swapKeyFileSeams(t)()
	stagingDirSeam(t)
	createKeyFile = func(string) (keyFileHandle, error) {
		return &fakeKeyFile{name: "/dev/shm/pm-luks/key-leak", failWrite: true}, nil
	}
	removeFile = func(string) error { return errIO }

	_, err := writeKeyFile(mustSecret(t, "x"))
	if err == nil {
		t.Fatal("writeKeyFile err = nil, want a failure")
	}
	if !strings.Contains(err.Error(), "write key file") {
		t.Errorf("err = %v, want the original write failure preserved", err)
	}
	if !strings.Contains(err.Error(), "cleanup failed") || !strings.Contains(err.Error(), "/dev/shm/pm-luks/key-leak") {
		t.Errorf("err = %v, want the key-file cleanup failure (plaintext residue) surfaced", err)
	}
}

// AddKey writes TWO key files; a failure on the second (new) must abort with no
// cryptsetup run.
func TestAddKey_SecondKeyFileFails(t *testing.T) {
	defer swapKeyFileSeams(t)()
	stagingDirSeam(t)
	removeFile = func(string) error { return nil }
	calls := 0
	// The first key file is REAL so it survives the identity capture and the
	// pre-exec re-check; only the second fails, which is what this pins.
	createKeyFile = func(dir string) (keyFileHandle, error) {
		calls++
		if calls == 2 {
			return nil, errIO // the "new" key file
		}
		f, err := os.CreateTemp(dir, "key-ok-*")
		if err != nil {
			return nil, err
		}
		return f, nil
	}
	r := &recordingRunner{}
	if err := mgr(t, r).AddKey(context.Background(), "/dev/sda2", mustSecret(t, "old"), mustSecret(t, "new"), AddKeyOptions{}); err == nil {
		t.Error("AddKey ignored a second key-file failure")
	}
	if len(r.calls) != 0 {
		t.Error("AddKey ran cryptsetup despite a key-file failure")
	}
}

// fakeScrubFile injects failures into cleanupKeyFile's scrub/close.
type fakeScrubFile struct {
	size      int64
	failWrite bool
	failClose bool
}

func (f *fakeScrubFile) Stat() (os.FileInfo, error) { return fakeInfo{f.size}, nil }
func (f *fakeScrubFile) WriteAt([]byte, int64) (int, error) {
	if f.failWrite {
		return 0, errIO
	}
	return 0, nil
}
func (f *fakeScrubFile) Close() error {
	if f.failClose {
		return errIO
	}
	return nil
}

type fakeInfo struct{ size int64 }

func (i fakeInfo) Name() string       { return "key" }
func (i fakeInfo) Size() int64        { return i.size }
func (i fakeInfo) Mode() fs.FileMode  { return 0o600 }
func (i fakeInfo) ModTime() time.Time { return time.Time{} }
func (i fakeInfo) IsDir() bool        { return false }
func (i fakeInfo) Sys() any           { return nil }

func TestCleanupKeyFile_FaultPaths(t *testing.T) {
	t.Run("open fails and remove fails → warns, no panic", func(t *testing.T) {
		defer swapKeyFileSeams(t)()
		openKeyFile = func(string) (scrubFile, error) { return nil, errIO }
		removeFile = func(string) error { return errIO }
		cleanupKeyFile("/dev/shm/pm-luks/key-x") // must not panic
	})
	t.Run("scrub + close + remove all fail → warns, no panic", func(t *testing.T) {
		defer swapKeyFileSeams(t)()
		openKeyFile = func(string) (scrubFile, error) {
			return &fakeScrubFile{size: 16, failWrite: true, failClose: true}, nil
		}
		removeFile = func(string) error { return errIO }
		cleanupKeyFile("/dev/shm/pm-luks/key-x") // exercises scrub/close/remove warn paths
	})
}
