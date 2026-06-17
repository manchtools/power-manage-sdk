//go:build !unix

package fs

// GetOwnership is unix-only: it relies on syscall.Stat_t to read the numeric
// uid/gid. On non-unix platforms (kept buildable for cross-platform `go vet`)
// it reports no ownership.
func GetOwnership(_ string) (owner, group string) { return "", "" }
