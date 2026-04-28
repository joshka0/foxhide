# PII Scrubbing LLM Proxy — Hardened Go POC

This is a small Go proof of concept for an LLM egress gateway. It accepts provider-shaped HTTP requests, scrubs PII and secrets before the request leaves your network, and then forwards the sanitized request to an upstream LLM API.

The important design choice is that the proxy is not just a generic NER classifier. It combines fast recognizers, JSON-path policy, sensitive-key handling, header/query protection, stable placeholders, and optional response-side transformation.

## What changed from the first POC

- **Configurable JSON policy**
  - `all_strings` mode scans nearly every JSON string except explicit exclusions.
  - `schema` mode scans only configured JSON paths such as `messages.*.content` and `input.*.content.*.text`.
- **Sensitive JSON key scrubbing**
  - Values under keys like `api_key`, `password`, `token`, `contact_email`, `account_id`, and `claim_number` are replaced even when the value itself is short or ambiguous.
- **Query parameter scrubbing**
  - Query values are scrubbed before the request is sent upstream.
- **Safer header forwarding**
  - By default the proxy drops inbound `Authorization`, `Cookie`, `X-Api-Key`, forwarding-IP headers, and related sensitive headers. Use environment-injected upstream auth instead.
- **Optional response scrubbing**
  - `SCRUB_RESPONSE=true` buffers and scans upstream responses before returning them to the caller.
- **Optional response rehydration**
  - `REHYDRATE_RESPONSE=true` replaces request-created placeholders such as `[EMAIL_1]` with the original values on the trusted return path only. New PII discovered during response scrubbing is not rehydrated.
- **Deny rules**
  - `DENY_ON_TYPES=SECRET,CREDIT_CARD` lets you fail closed for selected entity types instead of forwarding a sanitized request.
- **No raw prompt logging by default**
  - Logs include method, status, counts, entity categories, and latency. Request paths are redacted unless `LOG_REQUEST_PATH=true`.

## Detectors in this POC

The proxy has three detector layers:

- Gitleaks default secret rules, embedded through the official Go module.
- Optional local OpenAI `openai/privacy-filter` sidecar, exposed by the parent
  Node tool at `pnpm privacy:serve`.
- Standard-library Go recognizers, intended to be fast and dependency-free.

The Go layer still owns policy, placeholders, upstream forwarding, response
rehydration, denial rules, and logging. The model sidecar contributes additional
spans through `PRIVACY_FILTER_URL`.

- Emails
- US-style phone numbers, plus contextual 7-digit phones after words like `phone` or `call`
- SSNs with basic invalid-range filtering
- Credit cards with Luhn validation
- IPv4 and basic IPv6 addresses
- URLs with query strings
- JWTs, AWS-style access keys, OpenAI/Anthropic-looking keys, GitHub tokens, Slack tokens, Google API keys, bearer tokens, private-key blocks, and contextual secrets
- DOBs when context is present
- Contextual person names
- Contextual addresses
- Account, claim, policy, member, customer, patient, and case identifiers
- IBANs with checksum validation
- Contextual internal codenames/project names, such as `Internal codename Project Phoenix`

Repeated values within one request get stable placeholders:

```text
ann@example.com and ann@example.com
```

becomes:

```text
[EMAIL_1] and [EMAIL_1]
```

## Run in echo mode

Echo mode does not call an upstream provider. It returns the sanitized body and scrubbed query string so you can inspect what would be sent.

```bash
go run ./cmd/pii-proxy
```

With the local OpenAI privacy-filter sidecar:

```bash
# Terminal 1, from the repo root
pnpm privacy:serve

# Terminal 2, from pii-proxy/
PRIVACY_FILTER_URL=http://127.0.0.1:8090 go run ./cmd/pii-proxy
```

Then call it:

```bash
curl -s 'http://localhost:8080/v1/chat/completions?email=sarah.kim@example.com' \
  -H 'Content-Type: application/json' \
  -H 'X-Workspace-ID: local' \
  -H 'X-Conversation-ID: demo' \
  -d '{
    "model": "example-model",
    "messages": [
      {
        "role": "user",
        "content": "My name is Sarah Kim. Email sarah.kim@example.com, call 415-555-1212, claim number CLM-88317, card 4111 1111 1111 1111."
      }
    ]
  }' | jq
```

With the sidecar enabled, the proxy merges model detections with deterministic
Go rules and still returns stable placeholders:

```json
{
  "content": "Email me at [EMAIL_1] or call [PHONE_1]. Internal codename [MODEL_PRIVATE_1]."
}
```

Expected shape:

```json
{
  "mode": "echo",
  "redacted": true,
  "findings": {
    "CREDIT_CARD": 1,
    "EMAIL": 2,
    "ID": 1,
    "PERSON": 1,
    "PHONE": 1
  },
  "sanitized_query": "email=%5BEMAIL_1%5D",
  "sanitized_body": "..."
}
```

## Forward upstream

Set `UPSTREAM_BASE_URL` and inject provider auth from the proxy environment.

```bash
export UPSTREAM_BASE_URL='https://api.openai.com'
export UPSTREAM_AUTH_HEADER='Authorization'
export UPSTREAM_AUTH_VALUE="Bearer $OPENAI_API_KEY"
go run ./cmd/pii-proxy
```

For a local LM Studio OpenAI-compatible server:

```bash
# Terminal 1, from repo root
pnpm privacy:serve

# Terminal 2, from pii-proxy/
LISTEN_ADDR=127.0.0.1:8082 \
PRIVACY_FILTER_URL=http://127.0.0.1:8090 \
UPSTREAM_BASE_URL=http://127.0.0.1:1234/v1 \
REHYDRATE_RESPONSE=true \
go run ./cmd/pii-proxy
```

Then call the proxy instead of LM Studio directly:

```bash
curl -sS http://127.0.0.1:8082/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'X-Workspace-ID: local' \
  -H 'X-Conversation-ID: demo' \
  -d '{
    "model": "liquid/lfm2.5-1.2b",
    "messages": [
      {"role": "user", "content": "Contact me at josh@example.com or +1 415 555 0199. Internal codename Project Phoenix."}
    ],
    "temperature": 0,
    "max_tokens": 120
  }'
```

With `REHYDRATE_RESPONSE=true`, LM Studio receives placeholders such as
`[EMAIL_1]`, `[PHONE_1]`, and `[MODEL_PRIVATE_1]`; the trusted client receives
the originals restored in the response.

## Multi-user scoping and vaults

The proxy now scopes mappings by:

```text
org_id + workspace_id + conversation_id
```

This matters for multi-user and multi-turn use. The same original value gets
the same surrogate inside one conversation, but another workspace or
conversation gets an isolated mapping. `UserID` is stored for audit attribution,
not for surrogate isolation.

Local development uses header-derived identity:

```bash
AUTH_MODE=dev go run ./cmd/pii-proxy
```

Required headers:

```text
X-Workspace-ID
X-Conversation-ID
```

Optional dev headers:

```text
X-User-ID
X-Org-ID
```

For quick local smoke tests, you can relax the scope requirement:

```bash
REQUIRE_WORKSPACE=false REQUIRE_CONVERSATION=false go run ./cmd/pii-proxy
```

For EKS behind AWS ALB OIDC:

```bash
AUTH_MODE=alb_oidc \
ALLOWED_GROUPS=<azure-entra-group-id-or-role> \
ORG_ID=foxway \
go run ./cmd/pii-proxy
```

In `alb_oidc` mode the proxy reads the trusted ALB `x-amzn-oidc-data` header,
derives the user from `email`, `preferred_username`, `upn`, or `sub`, and can
gate access by `groups` or `roles`. Keep the service private to the ALB or
cluster network; do not expose the pod/service directly where that header could
be spoofed.

Vault options:

```bash
# Process-local only; good for development.
VAULT_BACKEND=memory

# Persistent multi-pod mappings; recommended for EKS.
VAULT_BACKEND=postgres \
DATABASE_URL='postgres://...' \
PII_HMAC_KEY='...' \
PII_ENCRYPTION_KEY='...' \
VAULT_AUTO_MIGRATE=true
```

The Postgres vault stores HMAC lookup keys and AES-GCM encrypted originals. It
also writes sanitized audit events with scope, user, model, entity counts,
denial status, and HTTP status. It does not store raw prompts.

## Transcript scrubbing

The proxy protects egress to the upstream model. Transcript storage is a
separate retention surface, so anything that writes local or hosted session
transcripts should scrub before persistence.

`cmd/pii-scrub` is a regex/Gitleaks-only scrubber for that path. It does not
call the model sidecar and does not persist a vault. By default it uses the same
Go deterministic PII recognizers plus Gitleaks' maintained default secret
rules.

Scrub stdin to stdout:

```bash
go build -o ./bin/pii-scrub ./cmd/pii-scrub
./bin/pii-scrub < transcript.txt > transcript.scrubbed.txt
```

Scrub files in place:

```bash
./bin/pii-scrub --in-place --json-summary ./transcripts/*.json
```

Use it as a guard before storing a transcript:

```bash
./bin/pii-scrub --check ./transcripts/session.json
```

`--check` exits `2` when findings are present. Use `--gitleaks=false` only for
fast local debugging; production transcript paths should leave Gitleaks enabled.

For Anthropic-style auth:

```bash
export UPSTREAM_BASE_URL='https://api.anthropic.com'
export UPSTREAM_AUTH_HEADER='x-api-key'
export UPSTREAM_AUTH_VALUE="$ANTHROPIC_API_KEY"
go run ./cmd/pii-proxy
```

Provider-specific non-secret headers, such as version headers, are still forwarded. Inbound auth/cookie headers are dropped by default.

## Policy modes

Default mode is privacy-biased:

```bash
SCRUB_JSON_MODE=all_strings go run ./cmd/pii-proxy
```

Schema-aware mode scans configured text-bearing fields and still redacts sensitive JSON keys:

```bash
POLICY_FILE=config/policy.schema.json go run ./cmd/pii-proxy
```

You can also configure paths directly:

```bash
export SCRUB_JSON_MODE=schema
export SCRUB_INCLUDE_PATHS='messages.*.content,input.*.content.*.text,system,instructions'
export SCRUB_EXCLUDE_PATHS='model,role,stream,temperature,tools.*.function.name'
go run ./cmd/pii-proxy
```

Path syntax is deliberately simple: dot-separated keys, with `*` matching one path segment. Arrays are represented as `*`, so `messages[0].content` is matched by `messages.*.content`.

## Useful environment variables

| Variable | Default | Meaning |
|---|---:|---|
| `LISTEN_ADDR` | `:8080` | Address for the proxy to bind |
| `UPSTREAM_BASE_URL` | empty | Empty means echo mode; otherwise requests are forwarded to this base URL |
| `UPSTREAM_AUTH_HEADER` | empty | Header to inject upstream, e.g. `Authorization` or `x-api-key` |
| `UPSTREAM_AUTH_VALUE` | empty | Auth header value |
| `MAX_BODY_BYTES` | `2097152` | Max request body size; also used for transformed response size |
| `UPSTREAM_TIMEOUT_SECONDS` | `60` | HTTP client timeout |
| `SCRUB_JSON_MODE` | `all_strings` | `all_strings` or `schema` |
| `POLICY_FILE` | empty | JSON policy file to load |
| `SCRUB_INCLUDE_PATHS` | default paths | Comma-separated JSON path patterns |
| `SCRUB_EXCLUDE_PATHS` | default excludes | Comma-separated JSON path patterns |
| `REDACT_SENSITIVE_JSON_KEYS` | `true` | Redact whole values under sensitive JSON keys |
| `SCRUB_PLAIN_TEXT` | `true` | Scrub non-JSON request bodies |
| `SCRUB_QUERY_PARAMS` | `true` | Scrub URL query values before forwarding |
| `FORWARD_SENSITIVE_HEADERS` | `false` | Forward inbound auth/cookie/IP headers; normally leave this false |
| `SCRUB_RESPONSE` | `false` | Buffer and scrub upstream responses |
| `REHYDRATE_RESPONSE` | `false` | Replace request-created placeholders in the response on the trusted side |
| `DENY_ON_TYPES` | empty | Comma-separated entity types to block, e.g. `SECRET,CREDIT_CARD` |
| `LOG_REQUEST_PATH` | `false` | Log raw request path; query strings are never needed in logs |
| `GITLEAKS_ENABLED` | `true` | Enable Gitleaks default secret rules in the proxy detector stack |
| `PRIVACY_FILTER_URL` | empty | Optional local sidecar URL, e.g. `http://127.0.0.1:8090` |
| `PRIVACY_FILTER_MIN_SCORE` | `0.85` | Minimum model token confidence accepted by the sidecar |
| `PRIVACY_FILTER_TIMEOUT_SECONDS` | `30` | Timeout for sidecar calls from Go |
| `AUTH_MODE` | `dev` | `dev` or `alb_oidc` |
| `ORG_ID` | `default` | Fallback org/tenant scope |
| `REQUIRE_WORKSPACE` | `true` | Require `X-Workspace-ID` |
| `REQUIRE_CONVERSATION` | `true` | Require `X-Conversation-ID` |
| `ALLOWED_GROUPS` | empty | Comma-separated allowed OIDC `groups` or `roles` |
| `VAULT_BACKEND` | `memory` | `memory` or `postgres` |
| `DATABASE_URL` | empty | Required when `VAULT_BACKEND=postgres` |
| `PII_HMAC_KEY` | empty | Required when `VAULT_BACKEND=postgres` |
| `PII_ENCRYPTION_KEY` | empty | Required when `VAULT_BACKEND=postgres` |
| `VAULT_AUTO_MIGRATE` | `true` | Create/update Postgres vault tables at startup |

## Response transformation notes

For lowest latency and streaming, leave both response flags false. The proxy then scrubs the request body and streams the upstream response back.

If `SCRUB_RESPONSE=true` or `REHYDRATE_RESPONSE=true`, the POC buffers the upstream response and asks the upstream server for an uncompressed body. That is simpler and safer for a POC, but for production you would add provider-specific SSE chunk handling and bounded streaming transforms.

## Blocking example

To prevent secrets from being sent upstream even after replacement:

```bash
export DENY_ON_TYPES=SECRET
go run ./cmd/pii-proxy
```

The proxy returns HTTP 400 with entity counts, but no raw sensitive values.

## Limitations

This is still a POC. It will miss ambiguous PII, unusual locale-specific identifiers, and indirect identifiers such as rare combinations of facts. It can also create false positives. Before production, add a reviewed golden corpus, locale-specific recognizers, per-tenant policy, structured metrics, load tests, streaming response transformation, and a formal privacy review.
