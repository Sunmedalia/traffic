#!/usr/bin/env bash
set -euo pipefail
[ "$(uname -s)" = Linux ] || { echo 'Build on Linux' >&2; exit 1; }
cd "$(dirname "$0")/.."
go mod download
go test -race ./...
go vet ./...
mkdir -p bin
go build -trimpath -o bin/traffic ./cmd/traffic
go build -trimpath -o bin/traffic-tui ./cmd/traffic-tui
sha256sum bin/traffic bin/traffic-tui > bin/SHA256SUMS
