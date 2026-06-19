package user

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

func TestGroupCreate_Golden(t *testing.T) {
	t.Run("minimal", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		if err := mgr(t, f).GroupCreate(context.Background(), "staff", GroupCreateOptions{}); err != nil {
			t.Fatal(err)
		}
		wantOneCmd(t, f, "groupadd", []string{"staff"}, true)
	})
	t.Run("system + gid", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		if err := mgr(t, f).GroupCreate(context.Background(), "svc", GroupCreateOptions{GID: 900, System: true}); err != nil {
			t.Fatal(err)
		}
		wantOneCmd(t, f, "groupadd", []string{"-g", "900", "-r", "svc"}, true)
	})
}

func TestGroupDelete_Golden(t *testing.T) {
	f := exectest.New(exec.Direct)
	if err := mgr(t, f).GroupDelete(context.Background(), "staff"); err != nil {
		t.Fatal(err)
	}
	wantOneCmd(t, f, "groupdel", []string{"staff"}, true)
}

func TestGroupEnsure(t *testing.T) {
	t.Run("exists → no groupadd", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		f.Push(exec.Result{ExitCode: 0}, nil) // getent group → exists
		if err := mgr(t, f).GroupEnsure(context.Background(), "staff"); err != nil {
			t.Fatal(err)
		}
		if len(f.Calls()) != 1 || f.Calls()[0].Name != "getent" {
			t.Errorf("expected only the existence probe, got %+v", f.Calls())
		}
	})
	t.Run("absent → groupadd", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		f.Push(exec.Result{ExitCode: 2}, nil) // getent group → absent
		f.Push(exec.Result{ExitCode: 0}, nil) // groupadd
		if err := mgr(t, f).GroupEnsure(context.Background(), "staff"); err != nil {
			t.Fatal(err)
		}
		calls := f.Calls()
		if len(calls) != 2 || calls[1].Name != "groupadd" {
			t.Errorf("expected probe + groupadd, got %+v", calls)
		}
	})
}

func TestAddRemoveGroup_Golden(t *testing.T) {
	f := exectest.New(exec.Direct)
	if err := mgr(t, f).AddToGroup(context.Background(), "deploy", "docker"); err != nil {
		t.Fatal(err)
	}
	wantOneCmd(t, f, "usermod", []string{"-aG", "docker", "deploy"}, true)

	f2 := exectest.New(exec.Direct)
	if err := mgr(t, f2).RemoveFromGroup(context.Background(), "deploy", "docker"); err != nil {
		t.Fatal(err)
	}
	wantOneCmd(t, f2, "gpasswd", []string{"-d", "deploy", "docker"}, true)
}

func TestGroupExistsAndMembers(t *testing.T) {
	t.Run("exists", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		f.Push(exec.Result{ExitCode: 0}, nil)
		ok, err := mgr(t, f).GroupExists(context.Background(), "staff")
		if err != nil || !ok {
			t.Errorf("GroupExists = (%v,%v), want (true,nil)", ok, err)
		}
	})
	t.Run("members parsed", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		f.Push(exec.Result{Stdout: "docker:x:999:deploy,ops\n"}, nil)
		members, err := mgr(t, f).GroupMembers(context.Background(), "docker")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(members, ",") != "deploy,ops" {
			t.Errorf("members = %v, want [deploy ops]", members)
		}
	})
	t.Run("no members → nil", func(t *testing.T) {
		f := exectest.New(exec.Direct)
		f.Push(exec.Result{Stdout: "docker:x:999:\n"}, nil)
		members, err := mgr(t, f).GroupMembers(context.Background(), "docker")
		if err != nil || members != nil {
			t.Errorf("members = (%v,%v), want (nil,nil)", members, err)
		}
	})
}

func TestGroupCreate_RejectsInvalidName(t *testing.T) {
	f := exectest.New(exec.Direct)
	if err := mgr(t, f).GroupCreate(context.Background(), "-evil", GroupCreateOptions{}); err == nil {
		t.Error("GroupCreate accepted a flag-shaped name")
	}
	if len(f.Calls()) != 0 {
		t.Error("ran groupadd for an invalid name")
	}
}

func TestMembersMatch(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{nil, nil, true},
		{[]string{}, nil, true},
		{[]string{"a", "b"}, []string{"b", "a"}, true},      // order-independent
		{[]string{"a", "a", "b"}, []string{"a", "b"}, true}, // dup-independent
		{[]string{"a"}, []string{"a", "b"}, false},
		{[]string{"a", "b"}, []string{"a", "c"}, false},
		{[]string{"x"}, nil, false},
	}
	for _, c := range cases {
		if got := MembersMatch(c.a, c.b); got != c.want {
			t.Errorf("MembersMatch(%v,%v) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestAddToGroup_MapsNonZeroExit(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{ExitCode: 6, Stderr: "usermod: group 'deployers' does not exist"}, nil)
	err := mgr(t, f).AddToGroup(context.Background(), "deploy", "deployers")
	var ce *exec.CommandError
	if !errors.As(err, &ce) || ce.ExitCode != 6 {
		t.Errorf("err = %v, want *exec.CommandError exit 6", err)
	}
}
