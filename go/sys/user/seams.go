package user

import "github.com/manchtools/power-manage/sdk/go/sys/fs"

// Package-var seams over the legacy fs helpers this package still calls (fs gains
// its own injected Runner in a later capability PR). Tests save/restore and
// override them to exercise the fs-touching branches — the Create -M+chown path
// and SetHiddenOnLoginScreen — without a real filesystem or privilege.
var (
	setOwnershipRecursive = fs.SetOwnershipRecursive
	writeFileAtomic       = fs.WriteFileAtomic
	removeStrict          = fs.RemoveStrict
)

// accountsServiceDir is the AccountsService per-user config directory. A var (not
// const) so tests can point it at a temp dir.
var accountsServiceDir = "/var/lib/AccountsService/users"
