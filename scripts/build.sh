#!/usr/bin/env bash
# Builds the Windows binaries into dist/<arch>/ from any OS.
#   ./scripts/build.sh            version from `git describe`
#   ./scripts/build.sh 1.0.0      explicit version
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${1:-$(git describe --tags --always 2>/dev/null || echo dev)}"
VERSION="${VERSION#v}"
LDFLAGS="-s -w -X main.version_=${VERSION} -buildid="
rm -rf dist
for arch in amd64 arm64; do
  mkdir -p "dist/${arch}"
  # zsp.exe: console client (credential_process, CLI) and the service binary.
  GOOS=windows GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS}" -o "dist/${arch}/zsp.exe" .
  # zspw.exe: the same program linked as a GUI app, so the watcher has no console window.
  GOOS=windows GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS} -H=windowsgui" -o "dist/${arch}/zspw.exe" .
done
(cd dist && sha256sum */*.exe > SHA256SUMS.txt && cat SHA256SUMS.txt)
