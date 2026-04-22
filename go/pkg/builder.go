package pkg

// InstallBuilder provides a fluent interface for installing packages.
type InstallBuilder struct {
	manager        Manager
	name           string
	version        string
	allowDowngrade bool
}

// Version sets the specific version to install.
func (b *InstallBuilder) Version(v string) *InstallBuilder {
	b.version = v
	return b
}

// AllowDowngrade permits downgrading if the installed version is higher.
func (b *InstallBuilder) AllowDowngrade() *InstallBuilder {
	b.allowDowngrade = true
	return b
}

// Run executes the install operation.
func (b *InstallBuilder) Run() (*CommandResult, error) {
	if b.version == "" && !b.allowDowngrade {
		return b.manager.Install(b.name)
	}
	return b.manager.InstallVersion(b.name, InstallOptions{
		Version:        b.version,
		AllowDowngrade: b.allowDowngrade,
	})
}

// RemoveBuilder provides a fluent interface for removing packages.
type RemoveBuilder struct {
	manager  Manager
	packages []string
	purge    bool
}

// Purge removes configuration files as well (apt only).
func (b *RemoveBuilder) Purge() *RemoveBuilder {
	b.purge = true
	return b
}

// Run executes the remove operation.
//
// Type-asserts the Manager against the Purger interface rather than
// the concrete *Apt type so validation-wrapped managers (from
// WithValidation / Detect) continue to dispatch to the purge path.
// A previous `b.manager.(*Apt)` shape silently degraded to Remove
// when the manager was wrapped, leaving apt package configs on
// disk under /etc/* despite the caller's Purge() request.
func (b *RemoveBuilder) Run() (*CommandResult, error) {
	if b.purge {
		if p, ok := b.manager.(Purger); ok {
			return p.Purge(b.packages...)
		}
	}
	return b.manager.Remove(b.packages...)
}

// UpgradeBuilder provides a fluent interface for upgrading packages.
type UpgradeBuilder struct {
	manager  Manager
	packages []string
}

// Run executes the upgrade operation.
func (b *UpgradeBuilder) Run() (*CommandResult, error) {
	return b.manager.Upgrade(b.packages...)
}

// PinBuilder provides a fluent interface for pinning packages.
type PinBuilder struct {
	manager  Manager
	packages []string
}

// Run executes the pin operation.
func (b *PinBuilder) Run() (*CommandResult, error) {
	return b.manager.Pin(b.packages...)
}

// UnpinBuilder provides a fluent interface for unpinning packages.
type UnpinBuilder struct {
	manager  Manager
	packages []string
}

// Run executes the unpin operation.
func (b *UnpinBuilder) Run() (*CommandResult, error) {
	return b.manager.Unpin(b.packages...)
}

// PackageManager wraps a Manager with builder pattern methods.
type PackageManager struct {
	Manager
}

// NewPackageManager creates a new PackageManager wrapping the given Manager.
func NewPackageManager(m Manager) *PackageManager {
	return &PackageManager{Manager: m}
}

// Install returns a builder for installing a package.
func (pm *PackageManager) Install(name string) *InstallBuilder {
	return &InstallBuilder{
		manager: pm.Manager,
		name:    name,
	}
}

// Remove returns a builder for removing packages.
func (pm *PackageManager) Remove(packages ...string) *RemoveBuilder {
	return &RemoveBuilder{
		manager:  pm.Manager,
		packages: packages,
	}
}

// Upgrade returns a builder for upgrading packages.
func (pm *PackageManager) Upgrade(packages ...string) *UpgradeBuilder {
	return &UpgradeBuilder{
		manager:  pm.Manager,
		packages: packages,
	}
}

// Pin returns a builder for pinning packages.
func (pm *PackageManager) Pin(packages ...string) *PinBuilder {
	return &PinBuilder{
		manager:  pm.Manager,
		packages: packages,
	}
}

// Unpin returns a builder for unpinning packages.
func (pm *PackageManager) Unpin(packages ...string) *UnpinBuilder {
	return &UnpinBuilder{
		manager:  pm.Manager,
		packages: packages,
	}
}

// New creates a PackageManager by auto-detecting the system's package manager.
func New() (*PackageManager, error) {
	m, err := Detect()
	if err != nil {
		return nil, err
	}
	return NewPackageManager(m), nil
}
