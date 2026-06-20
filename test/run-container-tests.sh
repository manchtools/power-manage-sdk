#!/bin/bash
#
# Runs the SDK's container-tagged real-execution tests.
#
# Usage:
#   ./sdk/test/run-container-tests.sh [distro] [state] [go-test-path]
#
# Defaults: debian / state-locked-apt / ./sdk/pkg/
#
# The tests run INSIDE the container (go test -tags=container), so the SDK's
# direct os.* filesystem access and its Runner-driven exec hit the same
# filesystem. Each test owns its precondition and self-skips when the baked
# state is absent, so running this against any stage is correct.
#
# Works with docker or podman (set CONTAINER_ENGINE).

set -euo pipefail

ENGINE="${CONTAINER_ENGINE:-docker}"
DISTRO="${1:-debian}"
STATE="${2:-state-locked-apt}"
TEST_PATH="${3:-./sdk/pkg/}"
IMAGE="pm-sdk-container-${DISTRO}-${STATE}"

# Build context is the repo root (parent of sdk/), matching the existing
# integration CI: the Dockerfile does `COPY sdk/ ./sdk/`.
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

echo "==> Building ${DISTRO}:${STATE} test image..."
"$ENGINE" build \
    -f "sdk/test/Dockerfile.${DISTRO}" \
    --target "${STATE}" \
    -t "${IMAGE}" \
    "$ROOT"

echo "==> Running container tests (${TEST_PATH}) inside ${STATE}..."
# --shm-size gives /dev/shm headroom for tests that stage container files there
# (e.g. the LUKS Manager's 64 MiB LUKS2 containers).
"$ENGINE" run --rm --shm-size=512m --cap-add NET_ADMIN "${IMAGE}" \
    go test -tags=container -count=1 -v "${TEST_PATH}" -run Container
