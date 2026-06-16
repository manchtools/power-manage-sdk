package user

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// SetHiddenOnLoginScreen shows or hides a user on the graphical login screen by
// setting/removing the AccountsService SystemAccount flag.
//
// (File writes still go through the legacy fs helpers; fs gains its own injected
// Runner in a later capability PR.)
func (u *shadowUtils) SetHiddenOnLoginScreen(ctx context.Context, name string, hidden bool) error {
	if err := validateUsername(name); err != nil {
		return err
	}
	configPath := filepath.Join(accountsServiceDir, name)

	if !hidden {
		// rm -f succeeds even if the file is absent.
		return removeStrict(ctx, configPath)
	}
	if _, err := os.Stat(accountsServiceDir); os.IsNotExist(err) {
		return fmt.Errorf("AccountsService not installed: %s not found", accountsServiceDir)
	}
	return writeFileAtomic(ctx, configPath, "[User]\nSystemAccount=true\n", "0644", "root", "root")
}
