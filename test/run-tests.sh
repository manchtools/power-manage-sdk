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
podman exec -w /workspace "$CONTAINER_NAME" \
    runuser -u power-manage -- /usr/local/go/bin/go test \
        -v -tags=integration -count=1 -timeout=10m \
        ./sdk/go/sys/exec/ ./sdk/go/sys/fs/ ./sdk/go/sys/user/ ./sdk/go/sys/systemd/
