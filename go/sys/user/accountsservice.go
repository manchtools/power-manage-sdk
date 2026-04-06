package user

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/manchtools/power-manage/sdk/go/sys/fs"
)

// accountsServiceDir is the directory where AccountsService stores per-user config.
const accountsServiceDir = "/var/lib/AccountsService/users"

// SetHiddenOnLoginScreen sets or clears the SystemAccount flag in
// AccountsService, which controls whether a user appears on the login screen.
//
// When hidden is true, the user's AccountsService file is created/updated
// with SystemAccount=true. When false, the setting is removed.
func SetHiddenOnLoginScreen(ctx context.Context, username string, hidden bool) error {
	if !IsValidName(username) {
		return fmt.Errorf("invalid username: %s", username)
	}

	configPath := filepath.Join(accountsServiceDir, username)

	if !hidden {
		// Remove the config file to unhide the user.
		// RemoveStrict uses rm -f, which already succeeds if the file doesn't exist.
		return fs.RemoveStrict(ctx, configPath)
	}

	// Check if AccountsService directory exists.
	if _, err := os.Stat(accountsServiceDir); os.IsNotExist(err) {
		return fmt.Errorf("AccountsService not installed: %s not found", accountsServiceDir)
	}

	content := "[User]\nSystemAccount=true\n"
	return fs.WriteFileAtomic(ctx, configPath, content, "0644", "root", "root")
}
