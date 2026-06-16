// Package user manages Linux user accounts and groups through an injected
// exec.Runner.
//
// Build a Manager for an explicit backend (shadow-utils is the only one today)
// and a Runner, then call its methods. The Manager owns OS mechanism and OS
// convention — the default-shell policy, the useradd -m/-M "home already exists"
// dance — while product policy (temporary-password records, SSH authorized_keys,
// hiding accounts) stays with the caller.
//
//	r, _ := exec.NewRunner(exec.Direct) // the agent runs as root; elsewhere: Sudo/Doas
//	um, _ := user.New(user.ShadowUtils, r)
//
//	// Create an interactive account with a home directory:
//	_ = um.Create(ctx, "deploy", user.CreateOptions{CreateHome: true})
//
//	// Set a generated password (carried as a redacted Secret):
//	pw, _ := user.GeneratePassword(16, user.ComplexityAlphanumeric)
//	_ = um.SetPassword(ctx, "deploy", pw)
//	_ = um.ExpirePassword(ctx, "deploy") // force change on first login
//
// Every mutating method validates the account/group name (IsValidName), so a
// name can never become a useradd/usermod flag or inject an extra chpasswd
// record. Passwords are exec.Secret values that render as "[REDACTED]" and only
// the chpasswd sink reveals their bytes.
//
// In tests, pass exectest.FakeRunner instead of a real Runner to assert the
// exact commands a Manager builds — no host, no sudo, no container.
package user
