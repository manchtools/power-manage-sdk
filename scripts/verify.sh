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

# buf runs from proto/ — there is no buf.yaml, so the module root is the cwd and
# `import "pm/v1/common.proto"` only resolves from there. CI sets
# working-directory: proto for exactly this reason.
#
# CI invokes it as `npx --prefix .. buf`, where `..` is the runner workspace;
# that path does not exist in the multi-repo checkout, so resolve buf the way it
# is actually available here.
buf_cmd() {
  if command -v buf >/dev/null 2>&1; then
    buf "$@"
  elif [ -x node_modules/.bin/buf ]; then
    "$PWD/node_modules/.bin/buf" "$@"
  else
    npx @bufbuild/buf "$@"
  fi
}

echo "== buf lint"
(cd proto && buf_cmd lint)

echo "== buf format (drift)"
(cd proto && buf_cmd format --diff --exit-code)

if ! command -v docref >/dev/null 2>&1; then
  echo "docref is not installed — the gate cannot certify this tree" >&2
  exit 1
fi
echo "== docref check"
docref check

echo "== SDK gate green"
