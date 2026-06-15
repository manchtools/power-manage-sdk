// Command protovalidatecoverage scans .proto files under the supplied
// directory and prints a human-readable summary of fields that lack a
// `validate:` constraint declared via the @gotags marker
// (protoc-go-inject-tag convention), across ALL messages (requests AND
// responses) for triage.
//
// It is a reporting tool only — it always exits 0. The authoritative CI gate
// is the Go test TestEveryBoundableRequestFieldCarriesValidateTag in
// coverage_test.go, which hard-fails when a bound-able *Request* field is
// missing a validate tag and runs under the normal `go test ./...` job. This
// binary stays useful for spotting untagged RESPONSE fields (which the gate
// deliberately does not require) when triaging coverage by hand.
//
// Usage:
//
//	go run ./test/protovalidatecoverage <proto-dir>
//
// Example:
//
//	go run ./test/protovalidatecoverage ./proto/pm/v1
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// fieldRE matches a proto field declaration line. The leading
// whitespace, the optional `optional`/`repeated`/`map<...>` qualifier,
// the type, the name, the field number, and any trailing options are
// captured loosely — we only need enough to recognise "this is a
// field" so we can pair it with an @gotags marker.
//
// Examples that match:
//
//	string id = 1;
//	repeated string permissions = 2;
//	optional bytes signature = 3;
//	map<string, string> labels = 4 [json_name = "labels"];
//	UserStatus status = 5;
var fieldRE = regexp.MustCompile(`^\s*(?:(?:optional|repeated|reserved)\s+)?(?:map<[^>]+>|[A-Za-z_][A-Za-z0-9_.]*)\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*\d+\s*(?:\[[^\]]*\])?\s*;\s*$`)

// gotagsRE detects a `// @gotags: ...` line. We only treat it as a
// validate cover if the captured tag list actually contains a
// `validate:"..."` segment.
var gotagsRE = regexp.MustCompile(`^\s*//\s*@gotags:\s*(.*)\s*$`)

// validateInGotagsRE asserts that a `// @gotags:` line carries a
// non-empty `validate:"..."` segment.
var validateInGotagsRE = regexp.MustCompile(`validate:"[^"]+"`)

// messageStartRE / messageEndRE keep us inside message scope so we
// don't count enum values or top-level options.
var (
	messageStartRE = regexp.MustCompile(`^\s*message\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{`)
	messageEndRE   = regexp.MustCompile(`^\s*\}\s*$`)
)

type fileReport struct {
	path             string
	totalFields      int
	uncoveredFields  int
	uncoveredSamples []string // up to 5 sample lines for human-readable output
}

func main() {
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: protovalidatecoverage <proto-dir>")
		os.Exit(2)
	}
	dir := flag.Arg(0)

	files, err := collectProtoFiles(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "walk %q: %v\n", dir, err)
		os.Exit(2)
	}
	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "no .proto files under %q\n", dir)
		os.Exit(2)
	}

	var reports []fileReport
	for _, p := range files {
		r, err := scanFile(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan %q: %v\n", p, err)
			os.Exit(2)
		}
		reports = append(reports, r)
	}

	sort.Slice(reports, func(i, j int) bool {
		return reports[i].uncoveredFields > reports[j].uncoveredFields
	})

	var totalFields, totalUncovered int
	fmt.Println("== Proto validate-tag coverage ==")
	fmt.Printf("%-44s  %8s  %8s  %8s\n", "file", "fields", "covered", "missing")
	for _, r := range reports {
		covered := r.totalFields - r.uncoveredFields
		fmt.Printf("%-44s  %8d  %8d  %8d\n", r.path, r.totalFields, covered, r.uncoveredFields)
		totalFields += r.totalFields
		totalUncovered += r.uncoveredFields
	}
	fmt.Println()
	fmt.Printf("TOTAL: %d fields, %d covered, %d missing.\n", totalFields, totalFields-totalUncovered, totalUncovered)

	if totalUncovered > 0 {
		fmt.Println()
		fmt.Println("== Sample of fields missing validate: tags (first 5 per file) ==")
		for _, r := range reports {
			if r.uncoveredFields == 0 {
				continue
			}
			fmt.Printf("\n# %s\n", r.path)
			for _, s := range r.uncoveredSamples {
				fmt.Println(s)
			}
			if r.uncoveredFields > len(r.uncoveredSamples) {
				fmt.Printf("... and %d more in this file\n", r.uncoveredFields-len(r.uncoveredSamples))
			}
		}
	}

	// Reporting tool only — always exits 0. The hard gate is the Go test
	// TestEveryBoundableRequestFieldCarriesValidateTag (request fields, type-aware).
	os.Exit(0)
}

func collectProtoFiles(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, ".proto") {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

func scanFile(p string) (fileReport, error) {
	r := fileReport{path: p}

	f, err := os.Open(p)
	if err != nil {
		return r, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// Some generated proto files have long lines (commented sample
	// data, large enum lists). Bump the buffer ceiling.
	sc.Buffer(make([]byte, 0, 1<<16), 1<<20)

	var (
		inMessage         bool
		messageStack      []string
		pendingValidate   bool
		pendingValidateLn string
		lineNum           int
	)

	for sc.Scan() {
		lineNum++
		line := sc.Text()

		// Track message scope. We need to be inside a message for a
		// field to count; top-level fields don't exist in proto3.
		if m := messageStartRE.FindStringSubmatch(line); m != nil {
			messageStack = append(messageStack, m[1])
			inMessage = true
			pendingValidate = false
			continue
		}
		if !inMessage {
			// Skip top-of-file noise.
			continue
		}
		if messageEndRE.MatchString(line) && len(messageStack) > 0 {
			messageStack = messageStack[:len(messageStack)-1]
			if len(messageStack) == 0 {
				inMessage = false
			}
			pendingValidate = false
			continue
		}

		// @gotags marker. The marker applies to the next field
		// declaration; we only count it as covered if the marker
		// actually contains a validate: clause.
		if m := gotagsRE.FindStringSubmatch(line); m != nil {
			if validateInGotagsRE.MatchString(m[1]) {
				pendingValidate = true
				pendingValidateLn = strings.TrimSpace(line)
			}
			continue
		}

		// Field declaration. Anything not matching is a comment,
		// blank line, nested oneof brace, etc. — leave the pending
		// marker alone so it still applies to the actual field below.
		if fieldRE.MatchString(line) {
			r.totalFields++
			if !pendingValidate {
				r.uncoveredFields++
				if len(r.uncoveredSamples) < 5 {
					r.uncoveredSamples = append(r.uncoveredSamples, fmt.Sprintf("  %s:%d  %s", p, lineNum, strings.TrimSpace(line)))
				}
			}
			pendingValidate = false
			pendingValidateLn = ""
		}
	}
	if err := sc.Err(); err != nil {
		return r, err
	}

	// pendingValidateLn is captured for future diagnostics but kept
	// out of the report today — the sampler above is enough signal
	// for operators to start triaging.
	_ = pendingValidateLn

	return r, nil
}
