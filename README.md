# hiemdall

Centralised authentication service for tb's applications.
Stateless microservice — no database, no session store. Google OAuth handshake only (v1).

**Stack:** Java 21, Spring Boot 3.3.4, Gradle 8.8, Spotless (Google Java Format AOSP).

---

## What it does today (v1)

Hiemdall acts as a shared Google OAuth gateway for registered downstream apps. A client app redirects its user to hiemdall, which handles the full OAuth 2.0 Authorization Code flow with Google and then redirects back to the app with identity resolved.

### Auth flow

```
Client App                   Hiemdall                         Google
    │                            │                               │
    ├─ GET /auth/google/start ──►│                               │
    │    ?app=kkt                │                               │
    │                            ├─ set csrf_state cookie        │
    │                            ├─ set post_login cookie        │
    │◄── 302 to Google ──────────┤                               │
    │                            │                               │
    ├────────────────────────────┼── user consents ─────────────►│
    │                            │                               │
    │                            │◄── 302 /auth/google/callback ─┤
    │                            │    ?code=...&state=...        │
    │                            │                               │
    │                            ├─ verify CSRF state            │
    │                            ├─ exchange code for tokens     │
    │                            ├─ decode OIDC id_token         │
    │                            ├─ extract IdentityClaims       │
    │                            │   (sub, email, name, picture) │
    │                            │                               │
    │◄── 302 to post-auth URL ──┤                               │
    │    (clear oauth cookies)   │                               │
```

### Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `GET` | `/auth/google/start?app={appId}` | Public | Initiate Google OAuth — sets cookies, 302s to Google |
| `GET` | `/auth/google/callback` | Public | Google redirects here after consent. Exchanges code, resolves identity, 302s to app |
| `GET` | `/api/actuator/health` | Public | Health check |
| `*` | `/internal/**` | `X-Internal-Auth` header | Service-to-service boundary (guarded by `InternalAuthFilter`) |

### Security boundaries

- `/auth/**` and `/api/actuator/**` — open, no Spring Security auth required.
- `/internal/**` — requires `X-Internal-Auth` header matching `app.internal.svc-token`. No controllers exist here yet; the filter is in place for v2.
- CSRF at the framework level is disabled. The OAuth flow uses per-request state cookies (`csrf_state`, `SameSite=Lax`).
- Stateless session policy — no `JSESSIONID`.

---

## Build & run

### Prerequisites

- Java 21+
- Google OAuth credentials (Client ID + Secret) from Google Cloud Console

### Local (Gradle)

```bash
./gradlew build          # compile + test
./gradlew bootRun        # run on port 9082
./gradlew bootJar        # fat JAR → build/libs/hiemdall-0.1.0-SNAPSHOT.jar
./gradlew spotlessApply  # format code (also: ./gradlew format)
./gradlew test           # tests only
```

Set env vars before `bootRun`:

```bash
export GOOGLE_CLIENT_ID=<your-client-id>
export GOOGLE_CLIENT_SECRET=<your-client-secret>
export APP_OAUTH_REDIRECT_URI=http://localhost:9082/auth/google/callback
```

Then visit: `http://localhost:9082/auth/google/start?app=kkt`

### Docker Compose

```bash
# one-time: create the shared network
docker network create tb-shared

# copy and fill in secrets
cp .env.example .env

# build JAR first, then start
./gradlew bootJar --no-daemon
docker compose up --build
```

The compose stack:
- Bind-mounts `config/registered-apps.yaml` into the container (read-only).
- Merges it into Spring config via `SPRING_CONFIG_IMPORT`.
- Secrets come from `.env` (gitignored).
- Runs on the `tb-shared` external network so other services can reach hiemdall.

---

## App registration

Hiemdall only serves apps that are explicitly registered. Registration is config-driven — no API, no database.

### How it works

Apps are declared under `app.registered-apps` in Spring config. Each entry maps an **app ID** (the key) to an app name and a post-auth redirect URL.

**Local dev** — defaults live in `application.yml`:

```yaml
app:
  registered-apps:
    kkt:
      app-name: KharchaKhata
      post-auth-redirect: http://localhost:9082/dashboard
```

**Production / Docker** — supply an external `registered-apps.yaml` file:

```yaml
# config/registered-apps.yaml
app:
  registered-apps:
    kkt:
      app-name: KharchaKhata
      post-auth-redirect: https://kkt.example.com/dashboard
    another-app:
      app-name: AnotherApp
      post-auth-redirect: https://another.example.com/callback
```

This file is bind-mounted into the container and merged via `SPRING_CONFIG_IMPORT`. To register a new app:

1. Add an entry to `registered-apps.yaml` with a unique app ID, name, and post-auth redirect URL.
2. Restart hiemdall.
3. The client app calls `/auth/google/start?app=<new-app-id>` to initiate login.

The `RegisteredApp` record requires both `appName` and `postAuthRedirect` (validated with `@NotBlank`). Unknown or missing `appId` on `/start` returns `400 Bad Request`.

---

## Configuration reference

### `application.yml`

| Key | Env override | Default | Purpose |
|-----|-------------|---------|---------|
| `server.port` | — | `9082` | Server port |
| `app.google.client-id` | `GOOGLE_CLIENT_ID` | — | Google OAuth Client ID |
| `app.google.client-secret` | `GOOGLE_CLIENT_SECRET` | — | Google OAuth Client Secret |
| `app.google.redirect-uri` | `APP_OAUTH_REDIRECT_URI` | `http://localhost:3000/api/auth/google/callback` | Where Google sends the auth code |
| `app.google.scopes` | — | `openid, email, profile, gmail.readonly` | OAuth scopes requested |
| `app.internal.svc-token` | `INTERNAL_SVC_TOKEN` | `dev-internal-token-change-me` | Shared secret for `/internal/**` |
| `app.registered-apps.*` | via `SPRING_CONFIG_IMPORT` | `kkt` only | App registry |

---

## Project structure

```
src/main/java/org/tb/hiemdall/
├── HiemdallApplication.java              # Spring Boot entry point
├── endpoints/
│   └── GoogleAuthRequestController.java  # /auth/google/* HTTP layer
├── services/
│   └── GoogleAuthServices.java           # Response builder (cookies, redirects)
├── auth/
│   ├── HiemdallAuthOrchestrator.java     # Interface: initiate + callback
│   ├── records/                          # DTOs (InitAuthRecord, AuthCallBackRecord,
│   │                                     #   IdentityClaims, OAuthTokenResponse,
│   │                                     #   HiemdallAuthResponseRecord)
│   ├── identity/
│   │   ├── IdentityResolver.java         # Interface: tokens → identity claims
│   │   └── oidc/
│   │       └── GoogleOIDCIdentityResolver.java
│   ├── utilities/                        # CSRF state, cookie helpers
│   ├── exception/                        # AuthFlowException hierarchy
│   └── gcp/
│       ├── GCPLoginOrchestrator.java     # Google impl of HiemdallAuthOrchestrator
│       ├── GCPAuthConstants.java         # Cookie names, paths, TTLs
│       ├── GoogleOAuthClient.java
│       ├── configs/
│       │   └── GoogleOAuthProperties.java
│       ├── clients/
│       │   └── GoogleTokenExchangeClient.java
│       ├── services/
│       │   ├── GoogleAuthStartService.java
│       │   ├── GoogleAuthCallbackService.java
│       │   └── GoogleLogoutService.java
│       └── contollers/
│           └── AuthExceptionHandler.java
├── security/
│   ├── config/
│   │   └── InternalAuthProperties.java
│   └── security/
│       └── InternalAuthFilter.java       # X-Internal-Auth header guard
└── spring/
    ├── SecurityConfig.java               # Spring Security wiring
    ├── RegisteredAppsConfig.java         # App registry bean
    └── RestClientBean.java
```

---

## What's next (v2)

JWT session token issuance — per-app RSA key pairs, JWKS endpoint (`/auth/jwks/{appId}`), token minting in the callback path. See `docs/design/spec/jwt_token_issuance.md` for the draft spec.
