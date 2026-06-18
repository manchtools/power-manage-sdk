package antivirus

import (
	"context"
	"fmt"
	"strings"

	"github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// clamavManager drives ClamAV via clamscan + freshclam.
type clamavManager struct {
	r exec.Runner
}

// Scan runs `clamscan -r --no-summary --infected -- <path>`. clamscan's exit
// codes: 0 = clean, 1 = virus(es) found, 2 = error. Exit 1 is NOT a failure — it
// is the "found something" signal — so 0 and 1 both parse the infected lines;
// only exit 2 (or a Runner failure) is an error.
func (m *clamavManager) Scan(ctx context.Context, path string) (ScanResult, error) {
	if err := validatePath(path); err != nil {
		return ScanResult{}, err
	}
	args := append([]string{"-r", "--no-summary", "--infected"}, exec.SeparatePositionals(nil, path)...)
	res, err := m.r.Run(ctx, exec.Command{Name: "clamscan", Args: args, Escalate: true})
	if err != nil {
		return ScanResult{}, fmt.Errorf("antivirus: run clamscan: %w", err)
	}
	if res.ExitCode != 0 && res.ExitCode != 1 {
		return ScanResult{}, &exec.CommandError{Name: "clamscan", ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return ScanResult{Path: path, Infected: parseClamscanInfected(res.Stdout)}, nil
}

// UpdateSignatures runs freshclam to refresh the signature database.
func (m *clamavManager) UpdateSignatures(ctx context.Context) error {
	res, err := m.r.Run(ctx, exec.Command{Name: "freshclam", Escalate: true})
	if err != nil {
		return fmt.Errorf("antivirus: run freshclam: %w", err)
	}
	if res.ExitCode != 0 {
		return &exec.CommandError{Name: "freshclam", ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return nil
}

// Version parses `clamscan --version` (unprivileged), e.g.
// "ClamAV 1.0.1/27000/Wed Jun 18 09:00:00 2025".
func (m *clamavManager) Version(ctx context.Context) (Version, error) {
	res, err := m.r.Run(ctx, exec.Command{Name: "clamscan", Args: []string{"--version"}})
	if err != nil {
		return Version{}, fmt.Errorf("antivirus: run clamscan --version: %w", err)
	}
	if res.ExitCode != 0 {
		return Version{}, &exec.CommandError{Name: "clamscan", ExitCode: res.ExitCode, Stderr: res.Stderr}
	}
	return parseClamscanVersion(res.Stdout)
}

// parseClamscanInfected extracts (file, signature) pairs from clamscan
// --infected output lines of the form "<file>: <signature> FOUND".
func parseClamscanInfected(out string) []Infection {
	var infected []Infection
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutSuffix(line, " FOUND")
		if !ok {
			continue
		}
		// The signature carries no ": ", so the LAST ": " separates file from
		// signature (a path may contain a colon, but not the "<colon><space>"
		// pair clamscan emits).
		i := strings.LastIndex(rest, ": ")
		if i < 0 {
			continue
		}
		infected = append(infected, Infection{File: rest[:i], Signature: rest[i+2:]})
	}
	return infected
}

// parseClamscanVersion parses the "ClamAV <engine>/<sig>/<date>" version line.
func parseClamscanVersion(out string) (Version, error) {
	line := strings.TrimSpace(out)
	if !strings.HasPrefix(line, "ClamAV ") {
		return Version{}, fmt.Errorf("antivirus: unexpected clamscan --version output: %q", out)
	}
	line = strings.TrimPrefix(line, "ClamAV ")
	parts := strings.SplitN(line, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return Version{}, fmt.Errorf("antivirus: unexpected clamscan --version output: %q", out)
	}
	return Version{Engine: parts[0], Signature: parts[1]}, nil
}
