#!/usr/bin/env bash
# The SDK's canonical verification gate — what CI runs, in one place.
#
# verify-stamp.sh prefers this over its generic Go gate, and that matters here
# for two reasons. The generic gate runs `go build/vet/test ./...` from the repo
# root, which fails outright: the workspace go.work lists only agent and server,
# so the SDK is "outside module roots" and nothing runs. And it knows nothing
# about `buf lint` or `docref check`, so even once it ran it would stamp the
# most contract-sensitive repo in the tree green without checking the contract.
#
# GOWORK=off throughout: the SDK is a standalone module and must build as one,
# because that is how every consumer resolves it.
#
# No `buf breaking`. CI does not run it either — V1 is the only version and the
# project takes clean breaks rather than compat shims, so a breaking-change gate
# would fail by design on every intentional contract change.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT=$PWD
export GOWORK=off

echo "== gofmt"
# No `2>/dev/null || true`: that swallows gofmt FAILING (unparseable file, bad
# path) and reports an empty violation list, so the check passes precisely when
# it could not run.
unfmt=$(gofmt -l .)
if [ -n "$unfmt" ]; then
  echo "gofmt violations:" >&2
  echo "$unfmt" >&2
  exit 1
fi

echo "== go build"
go build ./...

echo "== go vet"
go vet ./...

# Fail closed on a MISSING tool. Skipping it and reporting green is the exact
# shape this gate exists to prevent: a pass that means "not checked".
if ! command -v staticcheck >/dev/null 2>&1; then
  echo "staticcheck is not installed — the gate cannot certify this tree" >&2
  exit 1
fi
echo "== staticcheck"
staticcheck ./...

echo "== go test"
go test ./... -count=1

# buf runs from proto/ — proto/buf.yaml is the module root, so
# `import "powermanage/v1/common.proto"` only resolves from there. CI sets
# working-directory: proto for exactly this reason.
#
# The binary is resolved by scripts/buf.sh, which is fail-closed to the single
# lockfile-pinned install at the repo root. It is a separate script rather than
# a function here because `make generate` below ALSO shells out to buf: with the
# resolution inlined in this file, the drift check would regenerate gen/ts with
# whatever `npx` picked while these two steps linted with the pinned copy, and
# the gate would certify a tree no single buf ever produced.
#
# This previously fell back to a PATH `buf` when the lock install was absent.
# That is not a fallback, it is an unpinned execution: on this machine
# `command -v buf` resolves a go-installed binary with no relation to
# package-lock.json, so a missing `npm ci` turned "the gate ran the pinned buf"
# into "the gate ran some buf" with no signal either way.
BUF="$REPO_ROOT/scripts/buf.sh"

echo "== buf lint"
(cd proto && "$BUF" lint)

echo "== buf format (drift)"
(cd proto && "$BUF" format --diff --exit-code)

if ! command -v docref >/dev/null 2>&1; then
  echo "docref is not installed — the gate cannot certify this tree" >&2
  exit 1
fi
echo "== docref check"
docref check

# Generated-code drift. Without this the gate passes on a tree whose .proto and
# gen/ disagree: buf lints the SOURCE while the contract test reads the stale
# generated descriptor, so an RPC can be added or removed and both halves report
# green while contradicting each other.
#
# The `// protoc vX.Y.Z` comment is excluded exactly as CI excludes it — it flips
# with every protoc release and is not semantic.
echo "== generated-code drift"
make generate >/dev/null
if ! git diff --exit-code -I '^//\s*protoc\s+v[0-9]+\.[0-9]+\(\.[0-9]+\)\?' -- gen/; then
  echo "generated code in gen/ drifted from the proto sources — run 'make generate' and commit the result" >&2
  exit 1
fi

# The TypeScript half of the contract. gen/ts ships to consumers in the npm
# release, so a gate that only builds Go certifies half an artifact.
echo "== TypeScript typecheck"
npm run typecheck

echo "== TypeScript tests"
npm test

echo "== SDK gate green"
