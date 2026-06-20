#!/bin/bash
#
# Runs SDK integration tests inside a systemd-enabled container.
#
# Usage:
#   ./sdk/test/run-tests.sh
#
# The container boots systemd as PID 1 (required for systemctl daemon-reload,
# enable, start, stop tests), then the tests run as the power-manage user.
#

set -euo pipefail

CONTAINER_NAME="pm-sdk-test-$$"
IMAGE_NAME="pm-sdk-test"

cleanup() {
    podman stop -t 2 "$CONTAINER_NAME" 2>/dev/null || true
    podman rm -f "$CONTAINER_NAME" 2>/dev/null || true
}
trap cleanup EXIT

echo "==> Building test image..."
podman build -f sdk/test/Dockerfile.integration -t "$IMAGE_NAME" .

echo "==> Starting systemd container..."
podman run -d --privileged --name "$CONTAINER_NAME" "$IMAGE_NAME"

echo "==> Waiting for systemd to boot..."
for i in $(seq 1 30); do
    if podman exec "$CONTAINER_NAME" systemctl is-system-running --wait 2>/dev/null; then
        break
    fi
    sleep 0.5
done

echo "==> Running integration tests..."
# Run under a non-English locale (default Japanese) so locale-fragile parsing of
# tool output is caught: any capability that matches an English error string
# without forcing LC_ALL=C (Command.CLocale) fails here. Override with
# PM_TEST_LOCALE=C (or zh_CN.UTF-8, etc.). The locale is generated in the image.
TEST_LOCALE="${PM_TEST_LOCALE:-ja_JP.UTF-8}"
echo "    (locale: ${TEST_LOCALE})"

# Integration-tagged packages that run in THIS systemd container — the set whose
# //go:build integration tests need systemd as PID 1. Kept explicit (it is an
# intentional subset of sys/, not every package), but each path is existence-
# checked below so a module rename/move can never again silently drop a package
# from the run (the paths read ./sdk/go/sys/... until the go/*→root move, and the
# stale list passed `go test` vacuously). Paths are relative to /workspace.
INTEGRATION_PKGS=(
    sdk/sys/exec
    sdk/sys/fs
    sdk/sys/user
    sdk/sys/service
)
for p in "${INTEGRATION_PKGS[@]}"; do
    if [ ! -d "$p" ]; then
        echo "ERROR: integration package path '$p' does not exist (stale after a rename/move?)" >&2
        exit 1
    fi
done

podman exec -w /workspace "$CONTAINER_NAME" \
    runuser -u power-manage -- env "LANG=${TEST_LOCALE}" "LC_ALL=${TEST_LOCALE}" \
        /usr/local/go/bin/go test \
        -v -tags=integration -count=1 -timeout=10m \
        "${INTEGRATION_PKGS[@]/#/./}"
