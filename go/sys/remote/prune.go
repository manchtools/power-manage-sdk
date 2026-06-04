package remote

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

// pruneTo brings the tree under dest to a subset: any regular file
// whose forward-slash relative path is NOT in keep gets removed, and
// any directory left empty afterwards gets removed too. The dest dir
// itself stays — pruneTo is a tree-tidier, not a deleter.
//
// Used by:
//   - S3 prefix sync (slice 12) — keep = the source's object set.
//   - the future Git source's worktree clean.
//   - (potentially) HTTP-extract when an additive overlay mode lands;
//     today the HTTP archive flow uses staging-swap which is a strict
//     mirror, so it doesn't need pruneTo. See http_archive.go's
//     fetchArchive comment.
//
// Keep keys are forward-slash relative paths. nil keep means "remove
// every regular file" (full clean).
//
// Safety: pruneTo refuses any dest the canWipe guard would refuse, so
// a bug upstream can't silently hand it /etc or "/". A missing dest is
// treated as a successful no-op (mirrors Wipe's ENOENT-tolerant
// semantics).
func pruneTo(dest string, keep map[string]struct{}) error {
	if err := canWipe(dest); err != nil {
		return err
	}
	if _, err := os.Stat(dest); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat dest %s: %w", dest, err)
	}

	// Two-pass walk: collect, then act. WalkDir's mid-walk Remove is
	// allowed by the stdlib but the rules around dir-vs-file ordering
	// are easy to get wrong; collecting first keeps the deletion order
	// deterministic.
	type victim struct {
		path string
		dir  bool
	}
	var victims []victim

	walkErr := filepath.WalkDir(dest, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == dest {
			return nil
		}
		rel, rerr := filepath.Rel(dest, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			// Decide later — only an empty dir gets removed.
			return nil
		}
		if _, ok := keep[rel]; !ok {
			victims = append(victims, victim{path: path, dir: false})
		}
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("walk %s: %w", dest, walkErr)
	}

	// Remove regular files first.
	for _, v := range victims {
		if err := os.Remove(v.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", v.path, err)
		}
	}

	// Now collect directories that ended up empty, in path-length DESC
	// order so children are removed before their parents.
	var dirs []string
	dirsWalkErr := filepath.WalkDir(dest, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == dest || !d.IsDir() {
			return nil
		}
		dirs = append(dirs, path)
		return nil
	})
	if dirsWalkErr != nil {
		return fmt.Errorf("walk %s: %w", dest, dirsWalkErr)
	}
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, d := range dirs {
		// os.Remove only succeeds when the dir is empty; that's exactly
		// the contract we want — survivors keep their containing dir.
		if err := os.Remove(d); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			// ENOTEMPTY is fine (survivors live here); anything else
			// surfaces.
			if !isNotEmptyErr(err) {
				return fmt.Errorf("rmdir %s: %w", d, err)
			}
		}
	}
	return nil
}

// isNotEmptyErr — os.Remove returns *PathError wrapping ENOTEMPTY on
// non-empty dirs. We want to treat that as "OK, this dir has survivors,
// leave it alone" while still surfacing any other failure.
func isNotEmptyErr(err error) bool {
	return errors.Is(err, syscall.ENOTEMPTY)
}
