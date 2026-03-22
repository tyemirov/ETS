# Ephemeral Token Service (ETS) — JWT + DPoP + Tiny JS SDK

ETS is a compact Go **gateway** that sits in front of any HTTP API so a
**front-end-only** app can call it **without exposing provider keys**.

* `POST /tvm/issue` — mint a **short-lived HS256 access token** bound to the browser’s **DPoP** key (`cnf.jkt`) after origin/rate admission checks.
* `POST /api` — verify **Origin allowlist**, **rate-limit**, **JWT**, **DPoP**, **replay protection** → **reverse-proxy** to your upstream API.
* `GET /health` — lightweight readiness probe (no auth required).
* **Built-in browser SDK** served at `/sdk/tvm.mjs` so integration is a **one-liner**.

> “`/api`” is used as the example **public** path. You can expose any path you want; just keep your reverse proxy and SDK options in sync.

---

## Why use this

* **No secrets in the browser.** Clients only hold a 5-minute, **DPoP-bound** token.
* **General-purpose.** Works for *any* JSON HTTP API (search, generation, tiles, internal tools).
* **No accounts or mTLS.** Capability tokens + DPoP.
* **Zero crypto in your app.** ETS serves a **tiny JS SDK** that handles keygen, token minting, and DPoP.

---

## What’s in the box

* **ETS service (Go)** with two endpoints: `/tvm/issue` and `/api`.
* **Health check** at `/health` for container orchestration probes.
* **Embedded SDK** served from `/sdk/tvm.mjs` (ES module).

  * Generates a browser **P-256** keypair (WebCrypto)
  * Mints/refreshes the short-lived token
  * Builds correct **DPoP ES256** JWS (JOSE r||s format)
  * Exposes `postJson()` and `fetchResponse()` convenience methods

---

## Request flow

```
Browser   ──(public JWK)──────────────────►  POST /tvm/issue
ETS ── checks origin allowlist + rate ───► mint HS256 JWT (5 min, cnf.jkt)

Browser   ──(Bearer JWT + DPoP)──────────►  POST /api
ETS ── Origin + rate + JWT + DPoP ───────► reverse-proxy to upstream
```

---

## Quick start (Docker Compose)

> **Important:** Describe every upstream via `UPSTREAM_ROUTES`. Each entry defines the **public path prefix** (e.g., `/api`, `/tiles`) and the upstream **base origin** (no path). ETS preserves whatever path/query the browser sends relative to that prefix. When `UPSTREAM_ROUTES` is omitted, ETS falls back to the legacy single `/api` route powered by `UPSTREAM_BASE_URL` + `UPSTREAM_SERVICE_SECRET`.

```yaml
version: "3.9"
services:
  ets:
    build: .
    ports: ["8080:8080"]
    environment:
      LISTEN_ADDR: ":8080"
      ORIGIN_ALLOWLIST: "https://loopaware.mprlab.com"
      TOKEN_LIFETIME_SECONDS: "300"
      TVM_JWT_HS256_KEY: "replace-with-strong-32B-secret"
      UPSTREAM_ROUTES: |
        [
          {
            "publicPath": "/api",
            "upstreamBaseUrl": "https://llm-proxy.mprlab.com",
            "credentials": {
              "query": {"key": "replace-with-llm-proxy-service-secret"}
            }
          }
        ]
      RATE_LIMIT_PER_MINUTE: "60"
      UPSTREAM_TIMEOUT_SECONDS: "40"

  upstream-service:
    image: your-upstream:latest
    expose: ["8080"]
```

Run `./bin/ets generate-jwt-key` (or the container equivalent) to populate
`TVM_JWT_HS256_KEY`. Add upstream credentials directly inside the `UPSTREAM_ROUTES`
JSON (e.g., `"query": {"key": "..."}`, `"headers": {"X-App": "ets"}`, or
`"bearerToken": "..."`). The legacy `UPSTREAM_SERVICE_SECRET` environment variable
still injects a `key` query parameter when `UPSTREAM_ROUTES` is not defined.

**Run as a binary (no container):**

```bash
go mod tidy && go build -o bin/ets .
LISTEN_ADDR=":8080" \
ORIGIN_ALLOWLIST="https://loopaware.mprlab.com" \
TOKEN_LIFETIME_SECONDS="300" \
TVM_JWT_HS256_KEY="replace-with-strong-32B-secret" \
UPSTREAM_ROUTES='[{"publicPath":"/api","upstreamBaseUrl":"https://llm-proxy.mprlab.com","credentials":{"query":{"key":"replace-with-llm-proxy-service-secret"}}}]' \
RATE_LIMIT_PER_MINUTE="60" \
UPSTREAM_TIMEOUT_SECONDS="40" \
./bin/ets
```

## Prebuilt Docker image

Published images are available on GitHub Container Registry and are rebuilt on every push to `master` and on tags:

```bash
docker pull ghcr.io/tyemirov/ets:latest

docker run --rm \
  -e LISTEN_ADDR=":8080" \
  -e ORIGIN_ALLOWLIST="https://loopaware.mprlab.com" \
  -e TVM_JWT_HS256_KEY="replace-with-strong-32B-secret" \
  -e UPSTREAM_ROUTES='[{"publicPath":"/api","upstreamBaseUrl":"https://llm-proxy.mprlab.com"}]' \
  ghcr.io/tyemirov/ets:latest
```

Use the same environment variables described in the configuration reference to match your deployment.

---

## CLI helpers

The binary exposes a helper for generating strong secrets:

```bash
go build -o bin/ets .
./bin/ets generate-jwt-key
```

The command prints `TVM_JWT_HS256_KEY=<hex>`; copy it into your environment or
`.env` files. Supply per-upstream credentials through `UPSTREAM_ROUTES` (see
below) or keep using `UPSTREAM_SERVICE_SECRET` for single-route deployments. You can also invoke
`./bin/ets serve`; running the binary without arguments still starts the
server.

---

## Reverse proxy (TLS, public)

Keep CORS in **ETS**. Ensure the proxy passes the client scheme (`X-Forwarded-Proto`) so DPoP `htu` matches.

### Nginx

```nginx
server {
  listen 443 ssl http2;
  server_name ets.mprlab.com;

  # ssl_certificate ...;  ssl_certificate_key ...;

  proxy_set_header X-Forwarded-Proto $scheme;

  location /tvm/issue { proxy_pass http://ets:8080/tvm/issue; }
  location /api       { proxy_pass http://ets:8080; }   # no rewrite needed

  location = /health  { return 200; }
}
```

### Caddy 2

```caddy
ets.mprlab.com {
	encode zstd gzip

	handle_path /tvm/issue* {
		reverse_proxy http://ets:8080 {
			header_up X-Forwarded-Proto {scheme}
			header_up Host {host}
		}
	}

	handle_path /api* {
		reverse_proxy http://ets:8080 {
			header_up X-Forwarded-Proto {scheme}
			header_up Host {host}
		}
	}

	respond /health 200
}
```

*If the proxy and ETS share a Docker network, point to `http://ets:8080`.*

---

## Front-end usage (with the built-in SDK)

You don’t write crypto. Import the module ETS serves and call **one function**.

```html
<script type="module">
  import { createGatewayClient } from "https://ets.mprlab.com/sdk/tvm.mjs";

  const gatewayClient = createGatewayClient({
    baseUrl: "https://ets.mprlab.com",
    // Optional if you expose a different public path:
    // apiPath: "/api",
    // tokenPath: "/tvm/issue",
  });

  // Call your protected upstream via ETS:
  const result = await gatewayClient.postJson({ any: "payload your upstream expects" });
  console.log(result);
</script>
```

* `postJson(payload, { path })` — sends JSON to `baseUrl + (path||apiPath)`; returns parsed JSON.
* `fetchResponse(payload, { path })` — same, but returns the raw `Response`.

You can route multiple backends by varying `path` (e.g., `"/api/search"`, `"/api/generate"`), all protected by the same checks.

---

## Configuration reference

| Env var                    | Req        | Example                                       | Default | Purpose                                     |
| -------------------------- | ---------- | --------------------------------------------- | ------- | ------------------------------------------- |
| `LISTEN_ADDR`              | no         | `:8080`                                       | `:8080` | Bind address.                               |
| `ORIGIN_ALLOWLIST`         | **yes**    | `https://loopaware.mprlab.com`                | —       | Exact Origins allowed (admission + CORS).   |
| `TOKEN_LIFETIME_SECONDS`   | no         | `300`                                         | `300`   | Access token TTL; keep short.               |
| `TVM_JWT_HS256_KEY`        | **yes**    | random 32+ bytes                              | —       | HS256 signing key for tokens.               |
| `UPSTREAM_BASE_URL`        | **yes**    | `https://llm-proxy.mprlab.com`                | —       | **Base origin only** (no path).             |
| `UPSTREAM_SERVICE_SECRET`  | no         | `super-secret-value`                          | —       | Injected as `key` query parameter for upstreams that expect a shared secret. |
| `RATE_LIMIT_PER_MINUTE`    | no         | `60`                                          | `60`    | Per Origin+IP limit per 60s window.         |
| `UPSTREAM_TIMEOUT_SECONDS` | no         | `40`                                          | `40`    | Per-request upstream timeout.               |

---

## Security model (concise)

* **Capability token**: HS256 JWT, audience-scoped to ETS, TTL ≈ 5 minutes.
* **Proof-of-possession**: Token carries `cnf.jkt` (JWK thumbprint). Each request must present a **DPoP** JWS signed by that key; ETS verifies method (`htm`) and URL (`htu`).
* **Replay defense**: In-memory `jti` cache until expiry.
* **Origin enforcement**: Exact allowlist; CORS headers added by ETS.
* **Rate limiting**: Per Origin + IP within a 60-second window.

**Scaling**: For multiple replicas, keep traffic sticky per client or back the `jti` cache with a shared store.

---

## Customizing paths / multiple APIs

* Public path is **your choice** (we use `/api` as the example).
* Keep the reverse proxy routes and SDK `apiPath` consistent.
* To protect multiple upstream routes, just call `postJson(payload, { path: "/api/whatever" })`. ETS applies the same checks before proxying.

---

## Troubleshooting

* **CORS blocked** → The app’s `Origin` must *exactly* match an entry in `ORIGIN_ALLOWLIST`.
* **`htu_mismatch`** → Ensure the reverse proxy sets `X-Forwarded-Proto` correctly; the browser URL must match what ETS computes.
* **`cnf_mismatch`** → Token was minted for a different DPoP key; re-mint after generating the keypair (SDK handles this).
* **502/504** → Verify `UPSTREAM_BASE_URL` and upstream health; adjust `UPSTREAM_TIMEOUT_SECONDS`.

---

## License

Add your preferred license text here.
