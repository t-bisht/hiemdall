# hiemdall

Centralised authentication gateway for tb's applications.

A **stateless** Spring Boot microservice that owns the OAuth 2.0 / OpenID Connect handshake with Google on behalf of every registered downstream app. Apps never see Google's client secret, never implement the Authorization Code flow, and never touch Google's token endpoint — they just redirect their users to hiemdall and read back a short-lived handoff code.

**Stack:** Java 21 · Spring Boot 3.3.4 · Gradle 8.8 · Spotless (Google Java Format AOSP).

---

## Why this exists

The problem hiemdall solves:

- Every new internal app re-implements the Google OAuth flow: client registration, redirect URIs, CSRF state cookies, token exchange, id_token decoding.
- Each app ends up handling raw Google tokens in the browser, in local storage, or in half-baked session stores.
- Rotating a Google OAuth client — or switching provider — means touching every app.

Hiemdall centralises the handshake. It is a single gatekeeper that:

1. Owns the Google OAuth client credentials and redirect URI.
2. Runs the Authorization Code + CSRF-state flow once, correctly, for every app.
3. Parks the resulting Google token bundle in-memory and hands the browser only an **opaque, single-use handoff code** — raw tokens never travel through the user's browser.
4. Lets the owning app's backend swap that code for the real tokens over a server-to-server call guarded by a shared internal secret.

No database. No session store. No cross-app state. Horizontally scalable only when sticky-routing the browser hop → exchange hop to the same instance (handoff store is per-process in v1).

---

## What it does today (v1)

Scope is deliberately narrow:

- Google OAuth 2.0 Authorization Code flow (OIDC).
- Opaque browser-side handoff + back-channel token exchange.
- Config-driven app registry (no DB, no admin API).
- `/internal/**` boundary protected by a shared-secret header filter.

**Explicitly out of scope for v1** — JWT session issuance, JWKS endpoint, per-app RSA keys, Bearer-token verification. These were stripped from the original fork and will return in v2.

### End-to-end flow

```
Browser                  Hiemdall                      Google                 App Backend
   │                        │                             │                         │
   ├─ /auth/google/start?app=kkt ─►                       │                         │
   │                        │                             │                         │
   │                        ├─ set csrf_state cookie      │                         │
   │                        ├─ set post_login cookie      │                         │
   │                        │   (value: "kkt|<redirect>") │                         │
   │◄── 302 to Google ──────┤                             │                         │
   │                        │                             │                         │
   ├────────────────────────┼── user consents ──────────►│                         │
   │                        │                             │                         │
   │                        │◄── 302 /auth/google/callback┤                         │
   │                        │    ?code=...&state=...      │                         │
   │                        │                             │                         │
   │                        ├─ verify CSRF (cookie ↔ state)                         │
   │                        ├─ POST /token exchange ─────►│                         │
   │                        │◄──── access/refresh/id_token┤                         │
   │                        ├─ decode OIDC id_token                                 │
   │                        ├─ build IdentityClaims                                 │
   │                        ├─ park bundle in HandoffStore                          │
   │                        │   → opaque code (32 random bytes, URL-safe b64)       │
   │                        │                                                       │
   │◄── 302 <app post-auth URL>?handoff=<code> ─────┤                               │
   │                        │                                                       │
   ├─ GET <app URL>?handoff=<code> ─────────────────┼───────────────────────────────►│
   │                        │                                                       │
   │                        │◄──── POST /internal/auth/exchange ───────────────────┤
   │                        │      X-Internal-Auth: <shared secret>                │
   │                        │      { "app":"kkt", "handoff":"<code>" }             │
   │                        │                                                       │
   │                        ├─── 200 OAuthTokenResponse ──────────────────────────►│
   │                        │     (atomic get-and-remove — replays return 404)      │
```

### Endpoints

| Method | Path                              | Auth                     | Purpose                                                             |
|--------|-----------------------------------|--------------------------|---------------------------------------------------------------------|
| `GET`  | `/auth/google/start?app={appId}`  | Public                   | Initiate Google OAuth. Sets `csrf_state` + `post_login` cookies, 302s to Google. |
| `GET`  | `/auth/google/callback`           | Public (CSRF via cookie) | Google redirects here. Verifies state, exchanges code, parks tokens, 302s to the app with `?handoff=<code>`. |
| `POST` | `/internal/auth/exchange`         | `X-Internal-Auth` header | App backend redeems a handoff code for the Google token bundle. Atomic single-use. |
| `GET`  | `/api/actuator/health`            | Public                   | Health check.                                                       |

### Security boundaries

- **`/auth/**` and `/api/actuator/**`** — open, no Spring Security auth.
- **`/internal/**`** — every request guarded by `InternalAuthFilter`; requires `X-Internal-Auth` matching `app.internal.svc-token`.
- **CSRF** — framework CSRF is disabled. The OAuth flow uses a per-request `csrf_state` cookie (`SameSite=Lax`, `HttpOnly`, short TTL) matched against Google's returned `state` param.
- **Session policy** — stateless; no `JSESSIONID`.
- **Handoff codes** — 32 random bytes (URL-safe base64, no padding), single-use, TTL ~60s, bound to the owning `appId`. A consume with a mismatched `appId` returns 404 — same response as unknown/expired — so a probing caller can't distinguish failure modes.
- **Tokens in the browser** — only the opaque handoff code touches the browser URL. Raw Google tokens stay server-side.

---

## How downstream apps integrate

Three touchpoints:

### 1. Register the app

Add the app ID to `config/registered-apps.yaml`:

```yaml
app:
  registered-apps:
    kkt:
      app-name: KharchaKhata
      post-auth-redirect: https://kkt.example.com/dashboard
```

The `postAuthRedirect` is where hiemdall will land the browser after a successful login, with `?handoff=<code>` appended.

### 2. Send users to hiemdall for login

From the app's "Sign in with Google" button, redirect the browser to:

```
https://hiemdall.example.com/auth/google/start?app=kkt
```

Hiemdall handles everything from here through Google consent and back.

### 3. Redeem the handoff code

When the browser lands on `<post-auth-redirect>?handoff=<code>`, the app's backend calls hiemdall's internal exchange endpoint:

```http
POST /internal/auth/exchange
Host: hiemdall.example.com
X-Internal-Auth: <shared secret from app.internal.svc-token>
Content-Type: application/json

{ "app": "kkt", "handoff": "<code>" }
```

**Response (200):**

```json
{
  "access_token":  "ya29....",
  "refresh_token": "1//04....",
  "id_token":      "eyJhbGc...",
  "expires_in":    3599,
  "scope":         "openid email profile https://www.googleapis.com/auth/gmail.readonly",
  "token_type":    "Bearer"
}
```

**Response (404)** — unknown / expired / already-consumed / wrong-app code. All failure modes collapse to a single 404 on purpose.

From here the app decides what to persist (user upsert, session token minting, refresh-token storage, etc.). Hiemdall holds nothing beyond the TTL window.

---

## App registration

Hiemdall only serves apps that are **explicitly registered**. Registration is config-driven — no API, no DB.

### Local dev

Defaults live in `application.yml`:

```yaml
app:
  registered-apps:
    kkt:
      app-name: KharchaKhata
      post-auth-redirect: http://localhost:9082/dashboard
```

### Production / Docker

Supply an external `registered-apps.yaml`:

```yaml
# config/registered-apps.yaml
app:
  registered-apps:
    kkt:
      app-name: KharchaKhata
      post-auth-redirect: https://kkt.example.com/dashboard
    another-app:
      app-name: AnotherApp
      post-auth-redirect: https://another.example.com/auth/callback
```

The compose stack bind-mounts this file into the container and merges it via `SPRING_CONFIG_IMPORT`.

To onboard a new app:

1. Add an entry with a unique app ID, name, and post-auth redirect URL.
2. Ensure the Google OAuth client has hiemdall's `/auth/google/callback` listed as an authorized redirect URI.
3. Restart hiemdall.
4. The app calls `/auth/google/start?app=<id>` to begin login and `/internal/auth/exchange` to redeem the handoff.

Unknown or missing `app` on `/start` returns `400 Bad Request`. Validation on `RegisteredApp` requires both `appName` and `postAuthRedirect` (`@NotBlank`).

---

## Build & run

### Prerequisites

- Java 21+
- A Google OAuth 2.0 client (Client ID + Secret) from the Google Cloud Console. The configured redirect URI on the client must match hiemdall's `app.google.redirect-uri` byte-for-byte.

### Local (Gradle)

```bash
./gradlew build          # compile + test
./gradlew bootRun        # run on port 9082
./gradlew bootJar        # fat JAR → build/libs/hiemdall-<version>.jar
./gradlew test
./gradlew spotlessApply  # format code (alias: ./gradlew format)
```

Minimum env for `bootRun`:

```bash
export GOOGLE_CLIENT_ID=<your-client-id>
export GOOGLE_CLIENT_SECRET=<your-client-secret>
export APP_OAUTH_REDIRECT_URI=http://localhost:9082/auth/google/callback
export INTERNAL_SVC_TOKEN=<shared-secret-for-/internal>
```

Then kick the flow:

```
http://localhost:9082/auth/google/start?app=kkt
```

### Docker Compose

```bash
# copy and fill in secrets
cp .env.example .env

# build the fat JAR, then start the stack
./gradlew bootJar --no-daemon
docker compose up --build
```

The compose stack:

- Pulls `obake/hiemdall:${HIEMDALL_IMAGE_TAG:-latest}` (publish with `./docker_build.sh --push` first).
- Bind-mounts `config/registered-apps.yaml` into the container read-only.
- Merges that file into Spring config via `SPRING_CONFIG_IMPORT`.
- Reads secrets and per-env overrides from `.env` (gitignored).

To join a shared Docker network with downstream services, uncomment the `networks:` block in `docker-compose.yml` and run `docker network create tb-shared` once on the host.

---

## Configuration reference

| Key                           | Env override              | Default                                            | Purpose                                              |
|-------------------------------|---------------------------|----------------------------------------------------|------------------------------------------------------|
| `server.port`                 | —                         | `9082`                                             | Server port                                          |
| `app.google.client-id`        | `GOOGLE_CLIENT_ID`        | —                                                  | Google OAuth Client ID                               |
| `app.google.client-secret`    | `GOOGLE_CLIENT_SECRET`    | —                                                  | Google OAuth Client Secret                           |
| `app.google.redirect-uri`     | `APP_OAUTH_REDIRECT_URI`  | `http://localhost:9082/auth/google/callback`       | Where Google sends the auth code                     |
| `app.google.scopes`           | —                         | `openid, email, profile, gmail.readonly`           | OAuth scopes requested                               |
| `app.google.access-type`      | —                         | `offline`                                          | Needed for a `refresh_token`                         |
| `app.google.prompt`           | —                         | `consent`                                          | Forces a refresh_token on every authorize            |
| `app.internal.svc-token`      | `INTERNAL_SVC_TOKEN`      | `dev-internal-token-change-me`                     | Shared secret guarding `/internal/**`                |
| `app.handoff.ttl`             | —                         | `PT60S`                                            | Handoff code lifetime (ISO-8601)                     |
| `app.handoff.max-entries`     | —                         | `10000`                                            | Hard cap on concurrent parked bundles                |
| `app.handoff.sweep-every`     | —                         | `PT10S`                                            | Background expired-entry sweeper cadence             |
| `app.registered-apps.*`       | via `SPRING_CONFIG_IMPORT` | `kkt` only                                        | App registry                                         |

---

## Project structure

```
src/main/java/org/tb/hiemdall/
├── HiemdallApplication.java                 # Spring Boot entry point
├── endpoints/
│   ├── GoogleAuthRequestController.java     # /auth/google/{start,callback}
│   └── InternalHandoffController.java       # /internal/auth/exchange
├── services/
│   └── GoogleAuthServices.java              # Cookies, redirects, handoff put/consume glue
├── auth/
│   ├── HiemdallAuthOrchestrator.java        # Interface: initiate + callback
│   ├── records/                             # DTOs (InitAuthRecord, AuthCallBackRecord,
│   │                                        #       IdentityClaims, OAuthTokenResponse,
│   │                                        #       HiemdallAuthResponseRecord)
│   ├── identity/
│   │   ├── IdentityResolver.java            # Interface: tokens → identity claims
│   │   └── oidc/GoogleOIDCIdentityResolver.java
│   ├── handoff/
│   │   ├── HandoffStore.java                # In-memory ConcurrentHashMap, atomic consume
│   │   ├── HandoffEntry.java                # Parked token bundle + appId + expiresAt
│   │   ├── HandoffStoreSweeper.java         # @Scheduled expiry sweeper
│   │   ├── HandoffProperties.java           # ttl / max-entries / sweep-every
│   │   ├── HandoffExchangeRequest.java      # /internal/auth/exchange body
│   │   └── HandoffStoreFullException.java   # → 503
│   ├── utilities/                           # CSRF state generator, cookie helpers
│   ├── exception/                           # AuthFlowException hierarchy
│   └── gcp/
│       ├── GCPLoginOrchestrator.java        # Google impl of HiemdallAuthOrchestrator
│       ├── GCPAuthConstants.java            # Cookie names, paths, TTLs
│       ├── GoogleOAuthClient.java
│       ├── configs/GoogleOAuthProperties.java
│       ├── clients/GoogleTokenExchangeClient.java
│       ├── services/
│       │   ├── GoogleAuthStartService.java
│       │   ├── GoogleAuthCallbackService.java
│       │   └── GoogleLogoutService.java
│       └── contollers/AuthExceptionHandler.java
├── security/
│   ├── config/InternalAuthProperties.java
│   └── security/InternalAuthFilter.java     # X-Internal-Auth header guard
└── spring/
    ├── SecurityConfig.java                  # Spring Security wiring
    ├── RegisteredAppsConfig.java            # App registry bean
    └── RestClientBean.java
```

---

## Conventions (repo-wide)

- **No database.** Do not add JPA, Flyway, JDBC, or persistence code without explicit approval. Stateless by design.
- Use the `libs.*` version catalog in `gradle/libs.versions.toml`; never hard-code versions in `build.gradle`.
- Spotless runs on `build`. Format-first: `./gradlew spotlessApply` before every commit.
- Keep the `InternalAuthFilter` + related exceptions in place even when no controllers live under `/internal/` — the boundary is load-bearing.

---

## Historical context

- Seeded by copying `kharchakhata/java/login_engine` (multi-project subproject) and flattening to a single Gradle project.
- Original package `org.tb.khata.login.*` renamed to `org.tb.hiemdall.*`; `LoginEngineApplication` → `HiemdallApplication`.
- Token persistence layer (LoginTokenService, LoginToken entity, TokenCipher, GoogleTokenRefresher, InternalTokenController) fully stripped for stateless mode.
- Session JWT layer (RsaKeyProvider, SessionJwtIssuer, SessionJwtVerifier, JwksController, JwtProperties, TimeConfig, UserContextRequiredException, `app.jwt.*` config, jjwt deps) stripped for v1 — Google OAuth handshake only. Returns in v2.

---

## What's next (v2)

- JWT session token issuance — per-app RSA key pairs, JWKS endpoint (`/auth/jwks/{appId}`), token minting in the callback path.
- Pluggable identity resolvers for non-Google providers (the `IdentityResolver` interface and `OAuthTokenResponse` shape already allow for this).
- Durable handoff store for multi-instance deployments (Redis or similar), replacing the per-process `ConcurrentHashMap`.
