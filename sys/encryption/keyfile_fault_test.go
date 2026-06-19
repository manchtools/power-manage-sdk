package encryption

import (
	"context"
	"errors"
	"io/fs"
	"os"
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

// swapKeyFileSeams installs fault-injecting key-file seams and returns a restore.
func swapKeyFileSeams(t *testing.T) func() {
	t.Helper()
	m, c, rm, o := mkdirAll, createKeyFile, removeFile, openKeyFile
	return func() { mkdirAll, createKeyFile, removeFile, openKeyFile = m, c, rm, o }
}

func TestWriteKeyFile_FaultPaths(t *testing.T) {
	t.Run("mkdir fails", func(t *testing.T) {
		defer swapKeyFileSeams(t)()
		mkdirAll = func(string, os.FileMode) error { return errIO }
		if _, err := writeKeyFile(mustSecret(t, "x")); err == nil {
			t.Error("writeKeyFile ignored a mkdir failure")
		}
	})
	t.Run("create fails", func(t *testing.T) {
		defer swapKeyFileSeams(t)()
		mkdirAll = func(string, os.FileMode) error { return nil }
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
			mkdirAll = func(string, os.FileMode) error { return nil }
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

// AddKey writes TWO key files; a failure on the second (new) must abort with no
// cryptsetup run.
func TestAddKey_SecondKeyFileFails(t *testing.T) {
	defer swapKeyFileSeams(t)()
	mkdirAll = func(string, os.FileMode) error { return nil }
	removeFile = func(string) error { return nil }
	calls := 0
	createKeyFile = func(string) (keyFileHandle, error) {
		calls++
		if calls == 2 {
			return nil, errIO // the "new" key file
		}
		return &fakeKeyFile{name: "/dev/shm/pm-luks/key-ok"}, nil
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
