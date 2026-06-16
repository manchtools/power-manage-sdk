package network

import (
	"os"
	"path/filepath"
)

// File-operation seams. These are package vars (defaulting to the real os
// functions) so the tests can inject I/O faults and exercise the fail-closed
// cleanup / rollback branches of this security-critical code (keyfile write,
// EAP-TLS cert staging swap) hermetically — the disciplined way to reach 100%
// coverage on fs-coupled paths without a real failing disk.
var (
	mkdirAll   = os.MkdirAll
	writeFile  = os.WriteFile
	readFile   = os.ReadFile
	renameFile = os.Rename
	statFile   = os.Stat
	removeAll  = os.RemoveAll
	removeFile = os.Remove
	createTemp = func(dir, pattern string) (keyfileHandle, error) { return os.CreateTemp(dir, pattern) }
)

// Path-resolution seams, used only by resolvePath (the symlink-aware
// CertDir-under-CertBaseDir validator). Behind seams so the defensive
// error branches — filepath.Abs failing, EvalSymlinks failing, the walk
// reaching the filesystem root — are reachable in tests without a broken host.
var (
	absPath      = filepath.Abs
	evalSymlinks = filepath.EvalSymlinks
	statResolve  = os.Stat
)

// keyfileHandle is the minimal subset of *os.File that writeKeyfile needs.
// Behind the createTemp seam so a test can inject per-step (Write/Chmod/Close)
// I/O failures; *os.File satisfies it.
type keyfileHandle interface {
	Name() string
	Write([]byte) (int, error)
	Chmod(os.FileMode) error
	Close() error
}
