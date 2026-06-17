//go:build unix

package fs

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// GetOwnership returns the current owner and group NAMES of path. It stats the
// path unprivileged (no Runner needed) and resolves the numeric uid/gid against
// the user/group database. Any failure — missing path, unreadable parent, an
// id with no name — yields empty strings for the affected field, matching the
// best-effort contract callers rely on.
func GetOwnership(path string) (owner, group string) {
	info, err := os.Stat(path)
	if err != nil {
		return "", ""
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", ""
	}
	if u, lookupErr := user.LookupId(strconv.FormatUint(uint64(st.Uid), 10)); lookupErr == nil {
		owner = u.Username
	}
	if g, lookupErr := user.LookupGroupId(strconv.FormatUint(uint64(st.Gid), 10)); lookupErr == nil {
		group = g.Name
	}
	return owner, group
}
