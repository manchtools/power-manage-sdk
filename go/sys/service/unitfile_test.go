package service

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/exec/exectest"
)

func TestWriteUnit(t *testing.T) {
	var got struct {
		path, content, mode, owner, group string
	}
	w, r := writeFileAtomic, removeStrict
	writeFileAtomic = func(_ context.Context, path, content, mode, owner, group string) error {
		got.path, got.content, got.mode, got.owner, got.group = path, content, mode, owner, group
		return nil
	}
	defer func() { writeFileAtomic, removeStrict = w, r }()

	content := "[Unit]\nDescription=demo\n[Service]\nExecStart=/usr/bin/true\n"
	if err := mgr(t, exectest.New(0)).WriteUnit(context.Background(), "demo.service", content); err != nil {
		t.Fatal(err)
	}
	if got.path != "/etc/systemd/system/demo.service" || got.content != content || got.mode != "0644" || got.owner != "root" || got.group != "root" {
		t.Errorf("WriteUnit wrote %+v", got)
	}
}

func TestWriteUnit_RejectsInvalidNameBeforeFS(t *testing.T) {
	called := false
	w, r := writeFileAtomic, removeStrict
	writeFileAtomic = func(context.Context, string, string, string, string, string) error { called = true; return nil }
	defer func() { writeFileAtomic, removeStrict = w, r }()

	if err := mgr(t, exectest.New(0)).WriteUnit(context.Background(), "evil", "x"); err == nil {
		t.Error("WriteUnit accepted a unit name without a valid type suffix")
	}
	if called {
		t.Error("WriteUnit touched the filesystem for an invalid unit name")
	}
}

func TestRemoveUnit(t *testing.T) {
	var removed string
	w, r := writeFileAtomic, removeStrict
	removeStrict = func(_ context.Context, path string) error { removed = path; return nil }
	defer func() { writeFileAtomic, removeStrict = w, r }()

	if err := mgr(t, exectest.New(0)).RemoveUnit(context.Background(), "demo.service"); err != nil {
		t.Fatal(err)
	}
	if removed != "/etc/systemd/system/demo.service" {
		t.Errorf("RemoveUnit removed %q", removed)
	}
}

func TestRemoveUnit_WrapsFSError(t *testing.T) {
	w, r := writeFileAtomic, removeStrict
	removeStrict = func(context.Context, string) error { return errors.New("read-only file system") }
	defer func() { writeFileAtomic, removeStrict = w, r }()

	err := mgr(t, exectest.New(0)).RemoveUnit(context.Background(), "demo.service")
	if err == nil {
		t.Fatal("RemoveUnit returned nil on an fs error, want a wrapped error")
	}
	if !strings.Contains(err.Error(), "demo.service") {
		t.Errorf("error %q should name the unit path", err.Error())
	}
}

func TestDetect(t *testing.T) {
	lp, marker := lookPath, systemdRunMarker
	defer func() { lookPath, systemdRunMarker = lp, marker }()

	existingDir := t.TempDir() // stands in for /run/systemd/system

	t.Run("systemd present", func(t *testing.T) {
		lookPath = func(string) (string, error) { return "/usr/bin/systemctl", nil }
		systemdRunMarker = existingDir
		got := Detect(context.Background())
		if len(got) != 1 || got[0] != Systemd {
			t.Errorf("Detect = %v, want [Systemd]", got)
		}
	})
	t.Run("systemctl missing", func(t *testing.T) {
		lookPath = func(string) (string, error) { return "", errors.New("not found") }
		systemdRunMarker = existingDir
		if got := Detect(context.Background()); len(got) != 0 {
			t.Errorf("Detect = %v, want empty when systemctl is missing", got)
		}
	})
	t.Run("not pid 1 (marker absent)", func(t *testing.T) {
		lookPath = func(string) (string, error) { return "/usr/bin/systemctl", nil }
		systemdRunMarker = filepath.Join(existingDir, "does-not-exist")
		if got := Detect(context.Background()); len(got) != 0 {
			t.Errorf("Detect = %v, want empty when /run/systemd/system is absent", got)
		}
	})
}

func TestValidateUnitName(t *testing.T) {
	valid := []string{
		"nginx.service", "dbus.socket", "fstrim.timer", "tmp.mount",
		"-.mount",                    // root mount legitimately starts with '-'
		"getty@tty1.service",         // instance unit
		"home-user.mount",            // path-derived
		`dev-disk-by\x2duuid.device`, // systemd-escape hex
	}
	for _, n := range valid {
		if err := ValidateUnitName(n); err != nil {
			t.Errorf("ValidateUnitName(%q) = %v, want nil", n, err)
		}
	}
	invalid := []string{
		"",                // empty
		"nginx",           // no type suffix
		"nginx.txt",       // unknown type
		".hidden.service", // leading dot
		"-rf",             // flag-shaped, no suffix
		"nginx.service\n", // trailing newline
		"a b.service",     // space
		"unit.SERVICE",    // wrong-case type
	}
	for _, n := range invalid {
		if err := ValidateUnitName(n); err == nil {
			t.Errorf("ValidateUnitName(%q) = nil, want an error", n)
		}
	}
}
