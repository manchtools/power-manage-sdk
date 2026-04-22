package pkg

// validatingManager wraps any Manager and runs ValidatePackageName /
// ValidatePackageNames against every public entry point that takes a
// package-name argument. Callers that obtain their Manager via the
// package-level New() / Detect() helpers (which is the common path,
// including the agent's internal/executor) get this protection for
// free. Users who instantiate NewApt / NewDnf / NewPacman / NewZypper
// / NewFlatpak directly can opt in explicitly via WithValidation.
//
// Methods whose argument is unavoidably free-form (Search queries,
// list operations) are passed through unchanged.
type validatingManager struct {
	Manager
}

// WithValidation returns m wrapped so that every package-name input
// is checked by ValidatePackageName before it reaches the concrete
// package manager. Nil m returns nil.
func WithValidation(m Manager) Manager {
	if m == nil {
		return nil
	}
	if _, already := m.(*validatingManager); already {
		return m
	}
	return &validatingManager{Manager: m}
}

// Purger is the opt-in interface package managers implement to signal
// they support `apt purge`-style removal (delete packages AND
// configuration files). Currently only apt honours this semantically;
// dnf/pacman/zypper have no equivalent and the RemoveBuilder falls
// back to plain Remove().
//
// validatingManager implements Purger when the wrapped Manager does,
// so `RemoveBuilder.Run()` continues to reach the underlying purge
// path through the validation wrapper. Without this interface, the
// builder's old `b.manager.(*Apt)` type assertion would fail against
// *validatingManager and silently degrade `.Purge()` to `.Remove()`,
// leaving /etc/* config files on disk on `apt` deployments.
type Purger interface {
	Purge(packages ...string) (*CommandResult, error)
}

// Purge forwards to the wrapped Manager if it implements Purger.
// Callers typically reach this via RemoveBuilder.Run(); direct
// invocation is valid too. Validation runs before dispatch; if the
// wrapped Manager does not implement Purger, fall back to Remove()
// so the caller never gets a silent no-op.
func (v *validatingManager) Purge(packages ...string) (*CommandResult, error) {
	if err := ValidatePackageNames(packages); err != nil {
		return nil, err
	}
	if p, ok := v.Manager.(Purger); ok {
		return p.Purge(packages...)
	}
	return v.Manager.Remove(packages...)
}

func (v *validatingManager) Install(packages ...string) (*CommandResult, error) {
	if err := ValidatePackageNames(packages); err != nil {
		return nil, err
	}
	return v.Manager.Install(packages...)
}

func (v *validatingManager) InstallVersion(name string, opts InstallOptions) (*CommandResult, error) {
	if err := ValidatePackageName(name); err != nil {
		return nil, err
	}
	return v.Manager.InstallVersion(name, opts)
}

func (v *validatingManager) Remove(packages ...string) (*CommandResult, error) {
	if err := ValidatePackageNames(packages); err != nil {
		return nil, err
	}
	return v.Manager.Remove(packages...)
}

func (v *validatingManager) Upgrade(packages ...string) (*CommandResult, error) {
	if err := ValidatePackageNames(packages); err != nil {
		return nil, err
	}
	return v.Manager.Upgrade(packages...)
}

func (v *validatingManager) Show(name string) (*Package, error) {
	if err := ValidatePackageName(name); err != nil {
		return nil, err
	}
	return v.Manager.Show(name)
}

func (v *validatingManager) ListVersions(name string) (*VersionInfo, error) {
	if err := ValidatePackageName(name); err != nil {
		return nil, err
	}
	return v.Manager.ListVersions(name)
}

func (v *validatingManager) IsInstalled(name string) (bool, error) {
	if err := ValidatePackageName(name); err != nil {
		return false, err
	}
	return v.Manager.IsInstalled(name)
}

func (v *validatingManager) GetInstalledVersion(name string) (string, error) {
	if err := ValidatePackageName(name); err != nil {
		return "", err
	}
	return v.Manager.GetInstalledVersion(name)
}

func (v *validatingManager) Pin(packages ...string) (*CommandResult, error) {
	if err := ValidatePackageNames(packages); err != nil {
		return nil, err
	}
	return v.Manager.Pin(packages...)
}

func (v *validatingManager) Unpin(packages ...string) (*CommandResult, error) {
	if err := ValidatePackageNames(packages); err != nil {
		return nil, err
	}
	return v.Manager.Unpin(packages...)
}

func (v *validatingManager) IsPinned(name string) (bool, error) {
	if err := ValidatePackageName(name); err != nil {
		return false, err
	}
	return v.Manager.IsPinned(name)
}
