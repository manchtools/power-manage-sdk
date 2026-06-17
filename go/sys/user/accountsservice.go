package user

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/manchtools/power-manage/sdk/go/sys/fs"
)

// SetHiddenOnLoginScreen shows or hides a user on the graphical login screen by
// setting/removing the AccountsService SystemAccount flag.
func (u *shadowUtils) SetHiddenOnLoginScreen(ctx context.Context, name string, hidden bool) error {
	if err := validateUsername(name); err != nil {
		return err
	}
	configPath := filepath.Join(accountsServiceDir, name)

	if !hidden {
		// rm -f succeeds even if the file is absent.
		return u.fsm.Remove(ctx, configPath)
	}
	if _, err := os.Stat(accountsServiceDir); os.IsNotExist(err) {
		return fmt.Errorf("AccountsService not installed: %s not found", accountsServiceDir)
	}
	return u.fsm.WriteFile(ctx, configPath, []byte("[User]\nSystemAccount=true\n"), fs.WriteOptions{Mode: 0o644, Owner: "root", Group: "root"})
}
