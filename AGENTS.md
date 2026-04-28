# AGENTS.md

This repo is Foxhide: a local PII and secret scrubbing shield for LLM traffic.

## Project Map

- `README.md`: human quick start and high-level architecture.
- `install.sh`: installs dependencies, downloads the model cache, tests Go, and
  builds local binaries.
- `src/`: Node ESM tools using `@huggingface/transformers`.
- `src/privacy-server.mjs`: local HTTP sidecar for `/healthz`, `/detect`, and
  `/redact`.
- `pii-proxy/`: Go proxy and scrubber module.
- `pii-proxy/cmd/pii-proxy`: HTTP proxy entrypoint.
- `pii-proxy/cmd/pii-scrub`: standalone transcript/file scrubber.
- `pii-proxy/internal/scrubber`: recognizers, policy, vaults, and placeholder
  logic.

## Setup

From the repo root:

```bash
./install.sh
```

The script expects `node`, `pnpm`, and `go` on `PATH`. It creates local build
artifacts under ignored paths:

- `node_modules/`
- `.models-cache/`
- `pii-proxy/bin/`

Do not commit generated binaries, model caches, dependency folders, `.env`
files, or benchmark caches.

## Development Loop

Run the sidecar:

```bash
pnpm privacy:serve
```

Run the proxy in echo mode:

```bash
cd pii-proxy
PRIVACY_FILTER_URL=http://127.0.0.1:8090 go run ./cmd/pii-proxy
```

Run tests:

```bash
cd pii-proxy
go test ./...
```

Try the transcript scrubber:

```bash
cd pii-proxy
go run ./cmd/pii-scrub --help
```

## Agent Rules

- Keep raw secrets, tokens, real personal data, and `.env` files out of commits.
- Prefer echo mode when testing proxy behavior unless the task explicitly needs
  a real upstream.
- When adding new recognizers or policy behavior, add focused Go tests under
  `pii-proxy/`.
- When changing Node sidecar behavior, verify both CLI redaction and HTTP
  sidecar behavior if the change touches shared logic.
- Preserve the proxy's default stance: drop inbound sensitive headers, avoid raw
  prompt logging, and require workspace/conversation scope in dev mode unless a
  test explicitly configures otherwise.
- Use `rg` for repo search.

## Key Commands

```bash
pnpm install
pnpm privacy:download
pnpm privacy:redact -- "Email me at josh@example.com" --text
pnpm privacy:serve

cd pii-proxy
go test ./...
go build -o ./bin/pii-proxy ./cmd/pii-proxy
go build -o ./bin/pii-scrub ./cmd/pii-scrub
```

## Configuration Notes

Common proxy variables:

- `PRIVACY_FILTER_URL=http://127.0.0.1:8090`
- `UPSTREAM_BASE_URL=http://127.0.0.1:1234/v1`
- `UPSTREAM_AUTH_HEADER=Authorization`
- `UPSTREAM_AUTH_VALUE=Bearer ...`
- `REHYDRATE_RESPONSE=true`
- `DENY_ON_TYPES=SECRET,CREDIT_CARD`
- `VAULT_BACKEND=memory` for local development
- `VAULT_BACKEND=postgres` with `DATABASE_URL`, `PII_HMAC_KEY`, and
  `PII_ENCRYPTION_KEY` for persistent deployments

See `pii-proxy/README.md` before changing auth, vault, ALB OIDC, or response
transformation behavior.
