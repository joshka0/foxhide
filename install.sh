#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: missing required command: $1" >&2
    exit 1
  fi
}

need node
need pnpm
need go

echo "==> Installing Node dependencies"
pnpm install

echo "==> Downloading local privacy-filter model cache"
pnpm privacy:download -- --skip-run

echo "==> Downloading Go modules"
(cd pii-proxy && go mod download)

echo "==> Running Go tests"
(cd pii-proxy && go test ./...)

echo "==> Building Go binaries"
mkdir -p pii-proxy/bin
(cd pii-proxy && go build -o ./bin/pii-proxy ./cmd/pii-proxy)
(cd pii-proxy && go build -o ./bin/pii-scrub ./cmd/pii-scrub)

cat <<'EOF'

Foxhide is installed.

Start the model sidecar:
  pnpm privacy:serve

Start the proxy in another terminal:
  cd pii-proxy
  PRIVACY_FILTER_URL=http://127.0.0.1:8090 ./bin/pii-proxy

Use echo mode first. Set UPSTREAM_BASE_URL only when you are ready to forward.
EOF
