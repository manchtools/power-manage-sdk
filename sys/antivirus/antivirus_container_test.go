//go:build container

// Container-based real-execution tests for the ClamAV antivirus backend. The
// fake-runner unit tests feed captured clamscan/freshclam output; these run the
// real clamscan + freshclam binaries inside the with-clamav image, so a change
// to clamscan's `--infected` line format, its exit-code contract (0 clean / 1
// found / 2 error), or freshclam's failure behaviour is caught here.
//
// The image bakes a tiny STATIC seed DB (two loose signature files): the
// canonical EICAR test file by MD5 hash (.hdb) and our marker string by byte
// pattern (.ndb). Detection is deterministic and hermetic — no ~300 MB official
// DB download. freshclam.conf is removed so UpdateSignatures exercises the real
// error-mapping path without touching the network.
//
// Runs in the container-tests lane (root) → Direct runner: Escalate is a no-op
// wrapper and clamscan/freshclam run as the already-root process, the same shape
// production drives when the agent is root.
package antivirus_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/manchtools/power-manage-sdk/sys/antivirus"
	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// marker is the exact string the baked custom .ndb signature matches. Keep in
// sync with test/Dockerfile.debian (with-clamav stage).
const marker = "PM-CLAMAV-TEST-MARKER"

func realAV(t *testing.T) antivirus.Manager {
	t.Helper()
	if !hasClamscan(t) {
		t.Skip("clamscan not installed here; ClamAV backend not exercisable")
	}
	r, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatalf("NewRunner(Direct): %v", err)
	}
	m, err := antivirus.New(antivirus.ClamAV, r)
	if err != nil {
		t.Fatalf("New(ClamAV): %v", err)
	}
	return m
}

func hasClamscan(t *testing.T) bool {
	t.Helper()
	return len(antivirus.Detect(context.Background())) > 0
}

func avCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestDetect_Container: with clamscan installed, Detect must report exactly
// [ClamAV].
func TestDetect_Container(t *testing.T) {
	if !hasClamscan(t) {
		t.Skip("clamscan not installed here")
	}
	got := antivirus.Detect(context.Background())
	if len(got) != 1 || got[0] != antivirus.ClamAV {
		t.Errorf("Detect = %v, want [clamav]", got)
	}
}

// TestScan_Clean_Container scans a file with no signature hit. Real clamscan
// exits 0 and the SDK must report a clean result (no infections, no error).
func TestScan_Clean_Container(t *testing.T) {
	m := realAV(t)
	dir := t.TempDir()
	clean := filepath.Join(dir, "clean.txt")
	if err := os.WriteFile(clean, []byte("nothing to see here\n"), 0o644); err != nil {
		t.Fatalf("write clean file: %v", err)
	}
	res, err := m.Scan(avCtx(t), clean)
	if err != nil {
		t.Fatalf("Scan(clean): %v", err)
	}
	if !res.Clean() {
		t.Errorf("clean file reported infected: %+v", res.Infected)
	}
}

// eicarString returns the canonical 68-byte EICAR antivirus test string. Built
// from parts so no verbatim EICAR literal sits in the source tree (a real
// scanner watching the repo would otherwise flag this file). Its MD5 is
// 44d88612fea8a8f36de82e1278abb02f — the hash the seed .hdb matches.
func eicarString() string {
	return `X5O!P%@AP[4\PZX54(P^)7CC)7}` + `$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
}

// TestScan_EICAR_Container is the headline real-detection test: the canonical
// EICAR test file (the industry-standard AV smoke test) must be detected by real
// clamscan via the seed .hdb MD5 signature. clamscan exits 1 (NOT a failure —
// the "found" signal) and emits "<file>: <sig> FOUND"; the SDK must parse that
// into an Infection whose File is the scanned path and whose Signature is the
// matched name. Pins parseClamscanInfected + the exit-1 handling against real
// output.
func TestScan_EICAR_Container(t *testing.T) {
	m := realAV(t)
	dir := t.TempDir()
	bad := filepath.Join(dir, "eicar.txt")
	if err := os.WriteFile(bad, []byte(eicarString()), 0o644); err != nil {
		t.Fatalf("write EICAR file: %v", err)
	}
	res, err := m.Scan(avCtx(t), bad)
	if err != nil {
		t.Fatalf("Scan(EICAR): %v", err)
	}
	if res.Clean() {
		t.Fatal("EICAR not detected — real clamscan + seed .hdb produced no infection")
	}
	if len(res.Infected) != 1 {
		t.Fatalf("want exactly 1 infection, got %d: %+v", len(res.Infected), res.Infected)
	}
	inf := res.Infected[0]
	if inf.File != bad {
		t.Errorf("Infection.File = %q, want %q", inf.File, bad)
	}
	if !strings.Contains(inf.Signature, "PM.Eicar.Test") {
		t.Errorf("Infection.Signature = %q, want it to carry the seed sig name PM.Eicar.Test", inf.Signature)
	}
}

// TestScan_Marker_Container exercises the byte-PATTERN signature path (.ndb),
// complementing EICAR's hash signature (.hdb): a file containing the seed marker
// must be detected too.
func TestScan_Marker_Container(t *testing.T) {
	m := realAV(t)
	dir := t.TempDir()
	bad := filepath.Join(dir, "marker.txt")
	if err := os.WriteFile(bad, []byte("leading junk "+marker+" trailing junk\n"), 0o644); err != nil {
		t.Fatalf("write marker file: %v", err)
	}
	res, err := m.Scan(avCtx(t), bad)
	if err != nil {
		t.Fatalf("Scan(marker): %v", err)
	}
	if res.Clean() || len(res.Infected) != 1 {
		t.Fatalf("marker not detected as exactly one infection: %+v", res.Infected)
	}
	if !strings.Contains(res.Infected[0].Signature, "PM.Marker.Test") {
		t.Errorf("Infection.Signature = %q, want it to carry the seed sig name PM.Marker.Test", res.Infected[0].Signature)
	}
}

// TestScan_InvalidPath_Container: a flag-shaped path is rejected by the SDK's
// validation BEFORE clamscan is ever invoked (no real exec).
func TestScan_InvalidPath_Container(t *testing.T) {
	m := realAV(t)
	if _, err := m.Scan(avCtx(t), "-rf"); err == nil {
		t.Error("Scan accepted a flag-shaped path; want ErrInvalidPath")
	}
}

// TestVersion_Container exercises Version against the real clamscan binary. The
// with-clamav image ships only a custom, UNVERSIONED .ndb (no official CVD/CLD),
// so real `clamscan --version` reports engine-only ("ClamAV <x.y.z>"). The SDK's
// signature-required contract (see TestParseClamscanVersion, which pins
// "ClamAV 1.0.1" without a signature field as malformed) therefore maps this to
// an error — the faithful "installed but no signature DB" state. The
// engine/signature/date happy-format parse is covered by the unit tests; its
// real-binary form needs an official signature DB (network) and is a documented
// residual.
func TestVersion_Container(t *testing.T) {
	m := realAV(t)
	if _, err := m.Version(avCtx(t)); err == nil {
		t.Error("Version against a signature-DB-less clamscan should error per the signature-required contract; got nil")
	}
}

// TestUpdateSignatures_Container drives the real freshclam binary. The image
// removes freshclam.conf, so bare `freshclam` fails fast on a missing config
// (exit != 0) with no network access — a deterministic exercise of the SDK's
// error-mapping (non-zero exit -> error). The successful network DB refresh is a
// documented residual (network-bound, non-deterministic in CI).
func TestUpdateSignatures_Container(t *testing.T) {
	m := realAV(t)
	if err := m.UpdateSignatures(avCtx(t)); err == nil {
		t.Error("UpdateSignatures with no freshclam config should surface freshclam's failure; got nil")
	}
}
