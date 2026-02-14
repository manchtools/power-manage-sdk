package pkg

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// MockManager is a mock implementation of the Manager interface for testing.
type MockManager struct {
	mu sync.Mutex

	// Configurable return values
	InfoReturn          struct{ Name, Version string }
	InfoError           error
	InstallReturn       *CommandResult
	InstallError        error
	InstallVersionReturn *CommandResult
	InstallVersionError error
	RemoveReturn        *CommandResult
	RemoveError         error
	UpdateReturn        *CommandResult
	UpdateError         error
	UpgradeReturn       *CommandResult
	UpgradeError        error
	SearchReturn        []SearchResult
	SearchError         error
	ListReturn          []Package
	ListError           error
	ListUpgradableReturn []PackageUpdate
	ListUpgradableError error
	ShowReturn          *Package
	ShowError           error
	ListVersionsReturn  *VersionInfo
	ListVersionsError   error
	IsInstalledReturn   bool
	IsInstalledError    error
	GetInstalledVersionReturn string
	GetInstalledVersionError  error
	PinReturn           *CommandResult
	PinError            error
	UnpinReturn         *CommandResult
	UnpinError          error
	ListPinnedReturn    []Package
	ListPinnedError     error
	IsPinnedReturn      bool
	IsPinnedError       error

	// Call tracking
	InstallCalls        [][]string
	InstallVersionCalls []struct {
		Name string
		Opts InstallOptions
	}
	RemoveCalls   [][]string
	UpgradeCalls  [][]string
	SearchCalls   []string
	ShowCalls     []string
	PinCalls      [][]string
	UnpinCalls    [][]string
	PurgeCalls    [][]string
}

// Ensure MockManager implements Manager interface
var _ Manager = (*MockManager)(nil)

func NewMockManager() *MockManager {
	return &MockManager{
		InstallReturn:        &CommandResult{Success: true},
		InstallVersionReturn: &CommandResult{Success: true},
		RemoveReturn:         &CommandResult{Success: true},
		UpdateReturn:         &CommandResult{Success: true},
		UpgradeReturn:        &CommandResult{Success: true},
		PinReturn:            &CommandResult{Success: true},
		UnpinReturn:          &CommandResult{Success: true},
	}
}

func (m *MockManager) Info() (string, string, error) {
	return m.InfoReturn.Name, m.InfoReturn.Version, m.InfoError
}

func (m *MockManager) Install(packages ...string) (*CommandResult, error) {
	m.mu.Lock()
	m.InstallCalls = append(m.InstallCalls, packages)
	m.mu.Unlock()
	return m.InstallReturn, m.InstallError
}

func (m *MockManager) InstallVersion(name string, opts InstallOptions) (*CommandResult, error) {
	m.mu.Lock()
	m.InstallVersionCalls = append(m.InstallVersionCalls, struct {
		Name string
		Opts InstallOptions
	}{name, opts})
	m.mu.Unlock()
	return m.InstallVersionReturn, m.InstallVersionError
}

func (m *MockManager) Remove(packages ...string) (*CommandResult, error) {
	m.mu.Lock()
	m.RemoveCalls = append(m.RemoveCalls, packages)
	m.mu.Unlock()
	return m.RemoveReturn, m.RemoveError
}

func (m *MockManager) Update() (*CommandResult, error) {
	return m.UpdateReturn, m.UpdateError
}

func (m *MockManager) Upgrade(packages ...string) (*CommandResult, error) {
	m.mu.Lock()
	m.UpgradeCalls = append(m.UpgradeCalls, packages)
	m.mu.Unlock()
	return m.UpgradeReturn, m.UpgradeError
}

func (m *MockManager) Search(query string) ([]SearchResult, error) {
	m.mu.Lock()
	m.SearchCalls = append(m.SearchCalls, query)
	m.mu.Unlock()
	return m.SearchReturn, m.SearchError
}

func (m *MockManager) List() ([]Package, error) {
	return m.ListReturn, m.ListError
}

func (m *MockManager) ListUpgradable() ([]PackageUpdate, error) {
	return m.ListUpgradableReturn, m.ListUpgradableError
}

func (m *MockManager) Show(name string) (*Package, error) {
	m.mu.Lock()
	m.ShowCalls = append(m.ShowCalls, name)
	m.mu.Unlock()
	return m.ShowReturn, m.ShowError
}

func (m *MockManager) ListVersions(name string) (*VersionInfo, error) {
	return m.ListVersionsReturn, m.ListVersionsError
}

func (m *MockManager) IsInstalled(name string) (bool, error) {
	return m.IsInstalledReturn, m.IsInstalledError
}

func (m *MockManager) GetInstalledVersion(name string) (string, error) {
	return m.GetInstalledVersionReturn, m.GetInstalledVersionError
}

func (m *MockManager) Pin(packages ...string) (*CommandResult, error) {
	m.mu.Lock()
	m.PinCalls = append(m.PinCalls, packages)
	m.mu.Unlock()
	return m.PinReturn, m.PinError
}

func (m *MockManager) Unpin(packages ...string) (*CommandResult, error) {
	m.mu.Lock()
	m.UnpinCalls = append(m.UnpinCalls, packages)
	m.mu.Unlock()
	return m.UnpinReturn, m.UnpinError
}

func (m *MockManager) ListPinned() ([]Package, error) {
	return m.ListPinnedReturn, m.ListPinnedError
}

func (m *MockManager) IsPinned(name string) (bool, error) {
	return m.IsPinnedReturn, m.IsPinnedError
}

// Purge for testing RemoveBuilder.Purge() with non-Apt managers
func (m *MockManager) Purge(packages ...string) (*CommandResult, error) {
	m.mu.Lock()
	m.PurgeCalls = append(m.PurgeCalls, packages)
	m.mu.Unlock()
	return m.RemoveReturn, m.RemoveError
}

// =============================================================================
// Types Tests
// =============================================================================

func TestPackageStruct(t *testing.T) {
	pkg := Package{
		Name:         "nginx",
		Version:      "1.24.0",
		Architecture: "amd64",
		Description:  "High performance web server",
		Status:       "installed",
		Size:         1024000,
		Repository:   "main",
		Pinned:       false,
	}

	if pkg.Name != "nginx" {
		t.Errorf("expected Name to be 'nginx', got '%s'", pkg.Name)
	}
	if pkg.Size != 1024000 {
		t.Errorf("expected Size to be 1024000, got %d", pkg.Size)
	}
}

func TestCommandResult(t *testing.T) {
	result := CommandResult{
		Success:  true,
		ExitCode: 0,
		Stdout:   "output",
		Stderr:   "",
		Duration: 100 * time.Millisecond,
	}

	if !result.Success {
		t.Error("expected Success to be true")
	}
	if result.Duration != 100*time.Millisecond {
		t.Errorf("expected Duration to be 100ms, got %v", result.Duration)
	}
}

func TestInstallOptions(t *testing.T) {
	opts := InstallOptions{
		Version:        "1.24.0",
		AllowDowngrade: true,
	}

	if opts.Version != "1.24.0" {
		t.Errorf("expected Version '1.24.0', got '%s'", opts.Version)
	}
	if !opts.AllowDowngrade {
		t.Error("expected AllowDowngrade to be true")
	}
}

// =============================================================================
// Builder Pattern Tests
// =============================================================================

func TestInstallBuilder_Simple(t *testing.T) {
	mock := NewMockManager()
	pm := NewPackageManager(mock)

	result, err := pm.Install("nginx").Run()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if len(mock.InstallCalls) != 1 {
		t.Fatalf("expected 1 Install call, got %d", len(mock.InstallCalls))
	}
	if mock.InstallCalls[0][0] != "nginx" {
		t.Errorf("expected 'nginx', got '%s'", mock.InstallCalls[0][0])
	}
}

func TestInstallBuilder_WithVersion(t *testing.T) {
	mock := NewMockManager()
	pm := NewPackageManager(mock)

	_, err := pm.Install("nginx").Version("1.24.0").Run()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mock.InstallVersionCalls) != 1 {
		t.Fatalf("expected 1 InstallVersion call, got %d", len(mock.InstallVersionCalls))
	}
	call := mock.InstallVersionCalls[0]
	if call.Name != "nginx" {
		t.Errorf("expected name 'nginx', got '%s'", call.Name)
	}
	if call.Opts.Version != "1.24.0" {
		t.Errorf("expected version '1.24.0', got '%s'", call.Opts.Version)
	}
}

func TestInstallBuilder_WithAllowDowngrade(t *testing.T) {
	mock := NewMockManager()
	pm := NewPackageManager(mock)

	_, err := pm.Install("nginx").AllowDowngrade().Run()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mock.InstallVersionCalls) != 1 {
		t.Fatalf("expected 1 InstallVersion call, got %d", len(mock.InstallVersionCalls))
	}
	if !mock.InstallVersionCalls[0].Opts.AllowDowngrade {
		t.Error("expected AllowDowngrade to be true")
	}
}

func TestInstallBuilder_VersionAndAllowDowngrade(t *testing.T) {
	mock := NewMockManager()
	pm := NewPackageManager(mock)

	_, err := pm.Install("nginx").Version("1.22.0").AllowDowngrade().Run()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mock.InstallVersionCalls) != 1 {
		t.Fatalf("expected 1 InstallVersion call, got %d", len(mock.InstallVersionCalls))
	}
	call := mock.InstallVersionCalls[0]
	if call.Opts.Version != "1.22.0" {
		t.Errorf("expected version '1.22.0', got '%s'", call.Opts.Version)
	}
	if !call.Opts.AllowDowngrade {
		t.Error("expected AllowDowngrade to be true")
	}
}

func TestInstallBuilder_Error(t *testing.T) {
	mock := NewMockManager()
	mock.InstallError = errors.New("install failed")
	pm := NewPackageManager(mock)

	_, err := pm.Install("nginx").Run()

	if err == nil {
		t.Error("expected error, got nil")
	}
	if err.Error() != "install failed" {
		t.Errorf("expected 'install failed', got '%s'", err.Error())
	}
}

func TestRemoveBuilder_Simple(t *testing.T) {
	mock := NewMockManager()
	pm := NewPackageManager(mock)

	result, err := pm.Remove("nginx").Run()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if len(mock.RemoveCalls) != 1 {
		t.Fatalf("expected 1 Remove call, got %d", len(mock.RemoveCalls))
	}
}

func TestRemoveBuilder_Multiple(t *testing.T) {
	mock := NewMockManager()
	pm := NewPackageManager(mock)

	_, err := pm.Remove("nginx", "curl", "wget").Run()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mock.RemoveCalls) != 1 {
		t.Fatalf("expected 1 Remove call, got %d", len(mock.RemoveCalls))
	}
	if len(mock.RemoveCalls[0]) != 3 {
		t.Errorf("expected 3 packages, got %d", len(mock.RemoveCalls[0]))
	}
}

func TestRemoveBuilder_PurgeWithNonApt(t *testing.T) {
	// Purge with non-Apt manager should fall back to Remove
	mock := NewMockManager()
	pm := NewPackageManager(mock)

	_, err := pm.Remove("nginx").Purge().Run()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should call Remove since mock is not *Apt
	if len(mock.RemoveCalls) != 1 {
		t.Fatalf("expected 1 Remove call for non-Apt purge, got %d", len(mock.RemoveCalls))
	}
}

func TestUpgradeBuilder_All(t *testing.T) {
	mock := NewMockManager()
	pm := NewPackageManager(mock)

	_, err := pm.Upgrade().Run()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mock.UpgradeCalls) != 1 {
		t.Fatalf("expected 1 Upgrade call, got %d", len(mock.UpgradeCalls))
	}
	if len(mock.UpgradeCalls[0]) != 0 {
		t.Errorf("expected 0 packages (upgrade all), got %d", len(mock.UpgradeCalls[0]))
	}
}

func TestUpgradeBuilder_Specific(t *testing.T) {
	mock := NewMockManager()
	pm := NewPackageManager(mock)

	_, err := pm.Upgrade("nginx", "curl").Run()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mock.UpgradeCalls[0]) != 2 {
		t.Errorf("expected 2 packages, got %d", len(mock.UpgradeCalls[0]))
	}
}

func TestPinBuilder(t *testing.T) {
	mock := NewMockManager()
	pm := NewPackageManager(mock)

	_, err := pm.Pin("nginx", "curl").Run()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mock.PinCalls) != 1 {
		t.Fatalf("expected 1 Pin call, got %d", len(mock.PinCalls))
	}
	if len(mock.PinCalls[0]) != 2 {
		t.Errorf("expected 2 packages, got %d", len(mock.PinCalls[0]))
	}
}

func TestUnpinBuilder(t *testing.T) {
	mock := NewMockManager()
	pm := NewPackageManager(mock)

	_, err := pm.Unpin("nginx").Run()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mock.UnpinCalls) != 1 {
		t.Fatalf("expected 1 Unpin call, got %d", len(mock.UnpinCalls))
	}
}

// =============================================================================
// PackageManager Tests
// =============================================================================

func TestNewPackageManager(t *testing.T) {
	mock := NewMockManager()
	pm := NewPackageManager(mock)

	if pm.Manager != mock {
		t.Error("expected PackageManager to wrap the mock")
	}
}

func TestPackageManager_DirectAccess(t *testing.T) {
	mock := NewMockManager()
	mock.ListReturn = []Package{
		{Name: "nginx", Version: "1.24.0"},
	}
	pm := NewPackageManager(mock)

	// Test direct access to Manager methods
	packages, err := pm.List()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(packages) != 1 {
		t.Errorf("expected 1 package, got %d", len(packages))
	}
}

func TestPackageManager_Search(t *testing.T) {
	mock := NewMockManager()
	mock.SearchReturn = []SearchResult{
		{Name: "nginx", Description: "Web server"},
		{Name: "nginx-full", Description: "Full nginx"},
	}
	pm := NewPackageManager(mock)

	results, err := pm.Search("nginx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
	if mock.SearchCalls[0] != "nginx" {
		t.Errorf("expected search query 'nginx', got '%s'", mock.SearchCalls[0])
	}
}

func TestPackageManager_Show(t *testing.T) {
	mock := NewMockManager()
	mock.ShowReturn = &Package{
		Name:        "nginx",
		Version:     "1.24.0",
		Description: "High performance web server",
	}
	pm := NewPackageManager(mock)

	pkg, err := pm.Show("nginx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkg.Name != "nginx" {
		t.Errorf("expected 'nginx', got '%s'", pkg.Name)
	}
}

func TestPackageManager_ListVersions(t *testing.T) {
	mock := NewMockManager()
	mock.ListVersionsReturn = &VersionInfo{
		Name:      "nginx",
		Installed: "1.24.0",
		Versions: []AvailableVersion{
			{Version: "1.24.0", Repository: "stable"},
			{Version: "1.22.0", Repository: "oldstable"},
		},
	}
	pm := NewPackageManager(mock)

	info, err := pm.ListVersions("nginx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(info.Versions) != 2 {
		t.Errorf("expected 2 versions, got %d", len(info.Versions))
	}
	if info.Installed != "1.24.0" {
		t.Errorf("expected installed '1.24.0', got '%s'", info.Installed)
	}
}

func TestPackageManager_IsInstalled(t *testing.T) {
	mock := NewMockManager()
	mock.IsInstalledReturn = true
	pm := NewPackageManager(mock)

	installed, err := pm.IsInstalled("nginx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !installed {
		t.Error("expected package to be installed")
	}
}

func TestPackageManager_IsPinned(t *testing.T) {
	mock := NewMockManager()
	mock.IsPinnedReturn = true
	pm := NewPackageManager(mock)

	pinned, err := pm.IsPinned("nginx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !pinned {
		t.Error("expected package to be pinned")
	}
}

func TestPackageManager_ListPinned(t *testing.T) {
	mock := NewMockManager()
	mock.ListPinnedReturn = []Package{
		{Name: "nginx", Version: "1.24.0", Pinned: true},
	}
	pm := NewPackageManager(mock)

	pinned, err := pm.ListPinned()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pinned) != 1 {
		t.Errorf("expected 1 pinned package, got %d", len(pinned))
	}
}

func TestPackageManager_ListUpgradable(t *testing.T) {
	mock := NewMockManager()
	mock.ListUpgradableReturn = []PackageUpdate{
		{Name: "nginx", CurrentVersion: "1.22.0", NewVersion: "1.24.0"},
	}
	pm := NewPackageManager(mock)

	updates, err := pm.ListUpgradable()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(updates) != 1 {
		t.Errorf("expected 1 update, got %d", len(updates))
	}
}

func TestPackageManager_Update(t *testing.T) {
	mock := NewMockManager()
	pm := NewPackageManager(mock)

	result, err := pm.Update()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
}

func TestPackageManager_Info(t *testing.T) {
	mock := NewMockManager()
	mock.InfoReturn.Name = "apt"
	mock.InfoReturn.Version = "2.6.0"
	pm := NewPackageManager(mock)

	name, version, err := pm.Info()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "apt" {
		t.Errorf("expected name 'apt', got '%s'", name)
	}
	if version != "2.6.0" {
		t.Errorf("expected version '2.6.0', got '%s'", version)
	}
}

func TestPackageManager_GetInstalledVersion(t *testing.T) {
	mock := NewMockManager()
	mock.GetInstalledVersionReturn = "1.24.0-1ubuntu1"
	pm := NewPackageManager(mock)

	version, err := pm.GetInstalledVersion("nginx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "1.24.0-1ubuntu1" {
		t.Errorf("expected '1.24.0-1ubuntu1', got '%s'", version)
	}
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func TestInstallBuilder_InstallVersionError(t *testing.T) {
	mock := NewMockManager()
	mock.InstallVersionError = errors.New("version not found")
	pm := NewPackageManager(mock)

	_, err := pm.Install("nginx").Version("9.9.9").Run()

	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestRemoveBuilder_Error(t *testing.T) {
	mock := NewMockManager()
	mock.RemoveError = errors.New("package not installed")
	pm := NewPackageManager(mock)

	_, err := pm.Remove("nonexistent").Run()

	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestUpgradeBuilder_Error(t *testing.T) {
	mock := NewMockManager()
	mock.UpgradeError = errors.New("upgrade failed")
	pm := NewPackageManager(mock)

	_, err := pm.Upgrade().Run()

	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestPinBuilder_Error(t *testing.T) {
	mock := NewMockManager()
	mock.PinError = errors.New("pin failed")
	pm := NewPackageManager(mock)

	_, err := pm.Pin("nginx").Run()

	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestUnpinBuilder_Error(t *testing.T) {
	mock := NewMockManager()
	mock.UnpinError = errors.New("unpin failed")
	pm := NewPackageManager(mock)

	_, err := pm.Unpin("nginx").Run()

	if err == nil {
		t.Error("expected error, got nil")
	}
}

// =============================================================================
// Builder Chain Tests (Fluent API)
// =============================================================================

func TestInstallBuilder_ChainMethods(t *testing.T) {
	mock := NewMockManager()
	pm := NewPackageManager(mock)

	// Test that chain methods return the same builder
	builder := pm.Install("nginx")
	builder2 := builder.Version("1.24.0")
	builder3 := builder2.AllowDowngrade()

	if builder != builder2 || builder2 != builder3 {
		t.Error("chain methods should return the same builder instance")
	}
}

func TestRemoveBuilder_ChainMethods(t *testing.T) {
	mock := NewMockManager()
	pm := NewPackageManager(mock)

	builder := pm.Remove("nginx")
	builder2 := builder.Purge()

	if builder != builder2 {
		t.Error("chain methods should return the same builder instance")
	}
}

// =============================================================================
// Detection Tests
// =============================================================================

func TestDetect_Integration(t *testing.T) {
	// This test will succeed only on systems with apt or dnf
	manager, err := Detect()
	if err != nil {
		if err == ErrNoPackageManager {
			t.Skip("no supported package manager on this system")
		}
		t.Fatalf("unexpected error: %v", err)
	}

	name, _, err := manager.Info()
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}
	if name != "apt" && name != "dnf" {
		t.Errorf("expected 'apt' or 'dnf', got '%s'", name)
	}
}

func TestDetectWithContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	manager, err := DetectWithContext(ctx)
	if err != nil {
		if err == ErrNoPackageManager {
			t.Skip("no supported package manager on this system")
		}
		t.Fatalf("unexpected error: %v", err)
	}

	if manager == nil {
		t.Error("expected non-nil manager")
	}
}

func TestNew_Integration(t *testing.T) {
	pm, err := New()
	if err != nil {
		if err == ErrNoPackageManager {
			t.Skip("no supported package manager on this system")
		}
		t.Fatalf("unexpected error: %v", err)
	}

	if pm == nil {
		t.Error("expected non-nil PackageManager")
	}
	if pm.Manager == nil {
		t.Error("expected non-nil embedded Manager")
	}
}

func TestIsApt(t *testing.T) {
	// Just ensure the function doesn't panic
	_ = IsApt()
}

func TestIsDnf(t *testing.T) {
	// Just ensure the function doesn't panic
	_ = IsDnf()
}

// =============================================================================
// Empty Package List Tests
// =============================================================================

func TestInstall_EmptyList(t *testing.T) {
	mock := NewMockManager()

	result, err := mock.Install()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty install")
	}
	if len(mock.InstallCalls) != 1 {
		t.Errorf("expected 1 call, got %d", len(mock.InstallCalls))
	}
}

func TestRemove_EmptyList(t *testing.T) {
	mock := NewMockManager()

	result, err := mock.Remove()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty remove")
	}
}

func TestPin_EmptyList(t *testing.T) {
	mock := NewMockManager()

	result, err := mock.Pin()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty pin")
	}
}

func TestUnpin_EmptyList(t *testing.T) {
	mock := NewMockManager()

	result, err := mock.Unpin()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for empty unpin")
	}
}

// =============================================================================
// Concurrency Tests
// =============================================================================

func TestPackageManager_ConcurrentAccess(t *testing.T) {
	mock := NewMockManager()
	pm := NewPackageManager(mock)

	done := make(chan bool)

	// Run concurrent operations
	for i := 0; i < 10; i++ {
		go func() {
			_, _ = pm.Install("nginx").Run()
			_, _ = pm.List()
			_, _ = pm.IsInstalled("nginx")
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Just ensure no panics occurred
}
