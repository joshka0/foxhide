# Foxhide

Foxhide is a local privacy shield for LLM traffic. It detects private data and
secrets before prompts leave your machine or network, replaces them with stable
placeholders, and can forward the sanitized request to an OpenAI-compatible or
Anthropic-style upstream.

The repo contains two cooperating pieces:

- `src/`: a Node/Transformers.js sidecar for the `openai/privacy-filter` model.
  It exposes `/detect` and `/redact` over HTTP and can run from a local model
  cache.
- `pii-proxy/`: a Go proxy and transcript scrubber. It owns JSON policy,
  deterministic recognizers, Gitleaks secret detection, placeholder vaults,
  response rehydration, and upstream forwarding.

## Install

Prerequisites:

- Node.js 20 or newer
- `pnpm`
- Go 1.24 or newer

Then run:

```bash
./install.sh
```

The installer runs `pnpm install`, downloads the local privacy-filter model into
`.models-cache`, downloads Go modules, runs Go tests, and builds:

- `pii-proxy/bin/pii-proxy`
- `pii-proxy/bin/pii-scrub`

## Quick Start

Start the model sidecar from the repo root:

```bash
pnpm privacy:serve
```

In another terminal, start the Go proxy in echo mode:

```bash
cd pii-proxy
PRIVACY_FILTER_URL=http://127.0.0.1:8090 ./bin/pii-proxy
```

Send a request:

```bash
curl -sS http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'X-Workspace-ID: local' \
  -H 'X-Conversation-ID: demo' \
  -d '{
    "messages": [
      {
        "role": "user",
        "content": "Email me at josh@example.com or call +1 415 555 0199."
      }
    ]
  }' | jq
```

With no `UPSTREAM_BASE_URL`, the proxy returns an echo response showing the
sanitized request body and finding counts. This is the safest way to verify what
would be sent upstream.

## Forward To An LLM

Set an upstream base URL and inject provider auth from the proxy environment:

```bash
cd pii-proxy
UPSTREAM_BASE_URL=http://127.0.0.1:1234/v1 \
PRIVACY_FILTER_URL=http://127.0.0.1:8090 \
REHYDRATE_RESPONSE=true \
./bin/pii-proxy
```

For hosted APIs, provide the auth header/value the upstream expects:

```bash
UPSTREAM_BASE_URL=https://api.openai.com \
UPSTREAM_AUTH_HEADER=Authorization \
UPSTREAM_AUTH_VALUE="Bearer $OPENAI_API_KEY" \
./bin/pii-proxy
```

Inbound `Authorization`, cookies, API-key headers, and forwarding-IP headers are
dropped by default. Foxhide expects upstream credentials to be injected by the
proxy process, not accepted from callers.

## Transcript Scrubbing

Use the standalone scrubber before storing logs or agent transcripts:

```bash
pii-proxy/bin/pii-scrub < transcript.txt > transcript.scrubbed.txt
```

Check whether files contain findings without rewriting them:

```bash
pii-proxy/bin/pii-scrub --check ./transcripts/session.json
```

`--check` exits with code `2` when findings are present.

## Useful Commands

```bash
pnpm privacy -- "Email me at josh@example.com"
pnpm privacy:redact -- "Email me at josh@example.com" --text
pnpm privacy:bench -- --runs 10

cd pii-proxy
go test ./...
go run ./cmd/pii-proxy
go run ./cmd/pii-scrub --help
```

## Important Environment Variables

| Variable | Default | Meaning |
|---|---:|---|
| `PRIVACY_FILTER_URL` | empty | Optional sidecar URL, usually `http://127.0.0.1:8090` |
| `LISTEN_ADDR` | `:8080` | Proxy bind address |
| `UPSTREAM_BASE_URL` | empty | Empty means echo mode; otherwise forward to this base URL |
| `UPSTREAM_AUTH_HEADER` | empty | Header to inject upstream, such as `Authorization` |
| `UPSTREAM_AUTH_VALUE` | empty | Auth header value |
| `REHYDRATE_RESPONSE` | `false` | Restore request placeholders on the trusted response path |
| `SCRUB_RESPONSE` | `false` | Scrub new sensitive data in upstream responses |
| `DENY_ON_TYPES` | empty | Comma-separated entity types to block, such as `SECRET,CREDIT_CARD` |
| `VAULT_BACKEND` | `memory` | `memory` or `postgres` |
| `AUTH_MODE` | `dev` | `dev` or `alb_oidc` |

See `pii-proxy/README.md` for the full proxy configuration, policy modes,
Postgres vault setup, ALB OIDC mode, and deployment notes.

## How It Works

The sidecar runs `openai/privacy-filter` locally through Transformers.js. The Go
proxy combines that model output with deterministic recognizers and Gitleaks,
then rewrites JSON bodies, query parameters, and optionally responses. Repeated
values in the same org/workspace/conversation scope receive stable placeholders
such as `[EMAIL_1]`.

For local development, mappings live in memory. For multi-pod deployments, use
the Postgres vault so placeholders stay stable across requests while originals
are encrypted at rest.

## Limitations

Foxhide is a proof of concept. It can miss ambiguous, locale-specific, or
indirect identifiers and can produce false positives. Treat it as a strong
local guardrail, then add a reviewed golden corpus, tenant-specific policy,
metrics, load tests, and a privacy review before production use.
