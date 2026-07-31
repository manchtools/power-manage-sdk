#!/usr/bin/env bash
# The ONE buf this repository is allowed to run: the binary package-lock.json
# pinned, installed at the repo root by `npm ci`.
#
# Every buf invocation in this repo goes through here — the verification gate
# (scripts/verify.sh: lint + format-drift), code generation (Makefile:
# generate-ts) and CI. That is the point: a gate that lints the contract with
# one buf while generation writes gen/ts with a different one certifies a tree
# nothing ever built as a whole.
#
# Resolution is fail-closed and has exactly one candidate. There is deliberately
# NO fallback to a PATH `buf` and no `npx buf`, because both silently execute
# whatever version happens to be reachable:
#
#   - a PATH buf is whatever the developer or runner image installed globally
#     (here: a `go install`ed /home/…/go/bin/buf, unrelated to the lockfile);
#   - a bare `npx buf` / `npx @bufbuild/buf` DOWNLOADS registry-latest when the
#     package is not installed locally, so a missing `npm ci` turns into a
#     network fetch of unpinned code rather than an error.
#
# A verification gate must not execute code the lockfile did not pin, and it
# must not report green on a check it could not run. So a missing install is an
# instruction to the operator, not a download.
set -euo pipefail

# Resolved from THIS script's own location, not the caller's cwd: the gate runs
# `cd proto && …` (proto/buf.yaml is the module root, so `import "powermanage/v1/…"`
# only resolves from there) and make may be invoked with -C or -f from anywhere.
# A cwd-relative path silently missed the lock-installed binary and fell through
# to the PATH copy — the exact defect this script exists to remove.
REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BUF="$REPO_ROOT/node_modules/.bin/buf"

if [ ! -x "$BUF" ]; then
  echo "buf is not installed at $BUF" >&2
  echo "run 'npm ci' in $REPO_ROOT — this repo runs ONLY the lockfile-pinned buf;" >&2
  echo "there is no PATH fallback and nothing is fetched at run time." >&2
  exit 1
fi

# buf.gen.yaml declares `local: protoc-gen-es`, which buf resolves off PATH.
# That plugin is a devDependency too, and the old `npx @bufbuild/buf generate`
# found it only as a side effect of npx prepending node_modules/.bin. Invoking
# the binary directly drops that, so `generate` fails with "protoc-gen-es:
# executable file not found in $PATH" — and worse, on a machine that happens to
# have a global protoc-gen-es it would silently generate gen/ts with an
# unpinned code generator instead. Prepending (not appending) makes the
# lock-installed plugins win over anything global.
PATH="$REPO_ROOT/node_modules/.bin:$PATH"
export PATH

exec "$BUF" "$@"
