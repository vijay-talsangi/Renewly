# Renewly

Renewly is a subscription tracker with a browser sign-in flow, a REST API, and an **OAuth-protected MCP server** so AI clients such as Claude can read and manage a user's subscriptions.

A user signs in with an email and password, adds subscriptions, and connects an MCP client through OAuth 2.1. The MCP client never sees the user's password. It receives a scoped bearer token that is tied to that user's Renewly account.

**Repository:** <https://github.com/vijay-talsangi/Renewly>

---

## MCP server URL

**MCP Server URL:** `https://renewly-api-255909527631.asia-south1.run.app/mcp`

Use this URL when configuring Claude or any other MCP client.

---

## Table of contents

- [What Renewly does](#what-renewly-does)
- [Architecture](#architecture)
- [How it works](#how-it-works)
  - [Browser sign-in and sessions](#browser-sign-in-and-sessions)
  - [OAuth 2.1 for MCP clients](#oauth-21-for-mcp-clients)
  - [MCP server and tools](#mcp-server-and-tools)
  - [Renewal reminder worker](#renewal-reminder-worker)
- [Tech stack](#tech-stack)
- [Project layout](#project-layout)
- [Quick start](#quick-start)
  - [Prerequisites](#prerequisites)
  - [1. Clone the repository](#1-clone-the-repository)
  - [2. Configure environment variables](#2-configure-environment-variables)
  - [3. Set up PostgreSQL](#3-set-up-postgresql)
  - [4. Run the API](#4-run-the-api)
  - [5. Run the tests](#5-run-the-tests)
- [Configuration reference](#configuration-reference)
- [Sign-in and account flow](#sign-in-and-account-flow)
- [Connecting Claude](#connecting-claude)
- [Connecting a custom MCP client](#connecting-a-custom-mcp-client)
- [MCP tools](#mcp-tools)
- [REST API](#rest-api)
- [Deployment](#deployment)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Known limitations](#known-limitations)
- [License](#license)

---

## What Renewly does

- **Accounts** — register, sign in, view account status, and sign out.
- **Subscriptions** — create, list, update, and cancel subscriptions.
- **Upcoming bills** — find subscriptions renewing within a chosen number of days.
- **MCP integration** — exposes six MCP tools to Claude and other MCP clients.
- **OAuth 2.1 authorization server** — dynamic client registration, PKCE, consent screen, access and refresh tokens, revocation, and discovery metadata.
- **Email reminders** — a background worker sends renewal reminders 7 days, 2 days, and 1 day before a subscription renews, through [Resend](https://resend.com).
- **PostgreSQL storage** — users, subscriptions, OAuth clients, OAuth sessions, and reminder state live in PostgreSQL.

---

## Architecture

```text
┌────────────────────┐
│ Browser            │
│ login / register   │
│ consent UI         │
└─────────┬──────────┘
          │ HttpOnly JWT cookie + CSRF token
          ▼
┌─────────────────────────────────────────────┐
│ Renewly API (Go + Gin)                      │
│                                             │
│  /auth/*        server-rendered pages       │
│  /api/*         REST API                    │
│  /oauth/*       OAuth 2.1 endpoints         │
│  /mcp           MCP streamable HTTP         │
│  /.well-known/* OAuth discovery metadata    │
└──────────┬──────────────────────┬───────────┘
           │                      │
           │ SQL (pgx / sqlc)     │ OAuth bearer token
           ▼                      ▼
┌────────────────────┐   ┌─────────────────────┐
│ PostgreSQL         │   │ Claude / MCP client │
│ users              │   │ tools/list          │
│ subscriptions      │   │ tools/call          │
│ oauth_clients      │   └─────────────────────┘
│ oauth_sessions     │
│ reminders          │
└─────────┬──────────┘
          │
          ▼
┌──────────────────────────────┐
│ Reminder worker (Cloud Run   │
│ Job or local command)        │
│ 7 / 2 / 1 day reminders      │
└──────────────┬───────────────┘
               │ HTTPS
               ▼
        ┌─────────────┐
        │ Resend API  │
        └─────────────┘
```

The API and the reminder worker are built from the same repository. The web UI is embedded in the API binary with Go's `embed` package, so the runtime container only needs the compiled binary.

---

## How it works

### Browser sign-in and sessions

1. A visitor opens `/`. If there is no valid session, Renewly redirects to `/auth/login`.
2. New users create an account at `/auth/register`; existing users sign in at `/auth/login`.
3. Passwords are hashed with bcrypt. A successful login issues a signed **JWT** in the `auth_token` cookie.
4. The JWT is HS256-signed with `JWT_SECRET`, expires after 24 hours, and carries the user ID in the `sub` claim.
5. The cookie is `HttpOnly`, `SameSite=Lax`, and gets the `Secure` flag when `COOKIE_SECURE=true`.
6. HTML forms use a signed CSRF token stored in an `HttpOnly` nonce cookie and submitted as a hidden form field.
7. `/auth/status` shows the signed-in account and a sign-out button. Signing out clears the browser cookie only; OAuth grants issued to MCP clients stay valid until revoked.

The REST API can also be used directly:

- `POST /api/register`
- `POST /api/login` — sets the same `auth_token` cookie
- `POST /api/logout` — clears the cookie

### OAuth 2.1 for MCP clients

Renewly implements a small, purpose-built OAuth 2.1 authorization server using [Fosite](https://github.com/ory/fosite). It supports:

- **Dynamic client registration** at `POST /oauth/register` for public clients.
- **Authorization code flow** with **PKCE S256** (required).
- **Refresh tokens** for long-lived MCP connections.
- **Consent UI** showing the client name, signed-in account, and requested permissions.
- **Token revocation** at `POST /oauth/revoke`.
- **Discovery metadata** at `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource/mcp`.

Access tokens live for **15 minutes**; refresh tokens live for **30 days**. Only token signatures are stored in PostgreSQL, never the raw bearer token values.

The flow looks like this:

```text
MCP client                     Renewly                         User
    │                             │                              │
    │ 1. POST /oauth/register     │                              │
    │────────────────────────────>│                              │
    │<──── client_id ─────────────│                              │
    │                             │                              │
    │ 2. Open /oauth/authorize    │                              │
    │    + PKCE + state + resource│                              │
    │────────────────────────────>│── login/consent page ───────>│
    │                             │<──── user approves ──────────│
    │<── redirect with code ──────│                              │
    │                             │                              │
    │ 3. POST /oauth/token        │                              │
    │    code + code_verifier     │                              │
    │────────────────────────────>│                              │
    │<── access + refresh token ──│                              │
    │                             │                              │
    │ 4. POST /mcp                │                              │
    │    Authorization: Bearer …  │                              │
    │────────────────────────────>│                              │
    │<── tools/list, tools/call ──│                              │
```

Key OAuth endpoints:

| Endpoint | Purpose |
| --- | --- |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 authorization server metadata |
| `GET /.well-known/oauth-protected-resource/mcp` | RFC 9728 protected resource metadata |
| `POST /oauth/register` | Dynamic client registration (public clients only) |
| `GET /oauth/authorize` | Start authorization |
| `GET /oauth/consent` | Alias that redirects to `/oauth/authorize` |
| `POST /oauth/consent` | Submit allow/deny decision |
| `POST /oauth/token` | Exchange authorization code or refresh token |
| `POST /oauth/revoke` | Revoke a token |

The MCP audience is always `<OAUTH_ISSUER>/mcp`. A token is accepted by `/mcp` only when both the registered client and the granted token audience match that resource.

### MCP server and tools

The MCP endpoint is served at `/mcp` using the official [MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk) over **streamable HTTP**, in stateless mode with JSON responses.

Authentication is OAuth bearer only. The browser cookie is deliberately **not** accepted as an MCP credential. Every request is introspected, the token subject is parsed as a Renewly user ID, and that user ID is attached to the request context. Tools then use that ID for all database queries, so one user cannot read or modify another user's subscriptions.

### Renewal reminder worker

The `cmd/reminder_worker` binary:

1. Creates reminder rows for subscriptions renewing in **7**, **2**, or **1** day(s).
2. Claims work in batches with `SELECT … FOR UPDATE SKIP LOCKED`.
3. Sends email through Resend with an idempotency key.
4. Retries failed sends with backoff and records the error.
5. Avoids duplicate sends with a unique constraint on subscription, renewal date, and days-before.

In production this is deployed as a Cloud Run Job. The schedule itself is not defined in this repository; create a Cloud Scheduler trigger (for example, once per day) if you deploy the job.

---

## Tech stack

- **Go 1.26** (module: `github.com/vijay-talsangi/Renewly`)
- **Gin** for HTTP routing
- **PostgreSQL 17** with **pgx/v5**
- **sqlc** for type-safe SQL
- **goose** for migrations
- **Fosite** for OAuth 2.1
- **MCP Go SDK** for the MCP server
- **JWT** (`golang-jwt/jwt/v4`) and **bcrypt**
- **Resend** for transactional email
- **Docker** and **Google Cloud Build / Cloud Run**

---

## Project layout

```text
.
├── cmd/
│   ├── reminder_worker/       # renewal reminder job
│   └── test_email/            # manual Resend test command
├── config/                    # PostgreSQL pool configuration
├── controllers/               # REST API handlers
├── db/
│   ├── migration/             # goose migrations
│   ├── query/                 # sqlc SQL sources
│   └── sqlc/                  # generated query code
├── integration/               # API, database, and OAuth integration tests
├── internal/
│   ├── server/                # router, auth pages, CSRF
│   └── webui/                 # embedded login/register/consent templates
├── mcp/
│   ├── server.go              # streamable HTTP MCP handler
│   └── tools/                 # subscription MCP tools
├── middleware/                # JWT cookie authentication
├── oauth/                     # Fosite setup, storage, consent, continuations
├── services/                  # users, subscriptions, email, reminder worker
├── main.go                    # API entry point
├── Dockerfile
├── cloudbuild.yaml
├── docker-compose.yaml
└── Makefile
```

---

## Quick start

### Prerequisites

- Go **1.26.4** or newer
- PostgreSQL **14+** (17 is used in Docker Compose)
- `goose` for migrations
- Optional: `sqlc` if you change SQL queries
- A Resend API key if you want to send reminder emails

```bash
go install github.com/pressly/goose/v3/cmd/goose@latest
# optional:
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
```

### 1. Clone the repository

```bash
git clone git@github.com:vijay-talsangi/Renewly.git
cd Renewly
```

### 2. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` and fill in the values. At minimum you need `DATABASE_URL`, `JWT_SECRET`, `OAUTH_GLOBAL_SECRET`, and `OAUTH_ISSUER`.

Generate strong secrets:

```bash
openssl rand -hex 32   # use for JWT_SECRET
openssl rand -hex 32   # use for OAUTH_GLOBAL_SECRET
```

`OAUTH_GLOBAL_SECRET` must be at least 32 bytes and must remain stable across restarts and deployments, otherwise existing OAuth sessions can no longer be decoded.

For local development:

```dotenv
DATABASE_URL=postgresql://postgres:password@localhost:5432/subscription_db?sslmode=disable
JWT_SECRET=<random 32-byte value>
OAUTH_GLOBAL_SECRET=<random 32-byte value>
OAUTH_ISSUER=http://localhost:8080
COOKIE_SECURE=false
```

Never commit `.env`. It is already listed in `.gitignore` and `.dockerignore`.

### 3. Set up PostgreSQL

The included Compose file starts PostgreSQL only:

```bash
docker compose up -d postgres
```

Apply migrations:

```bash
make migrate-up
```

`make migrate-up` reads `DATABASE_URL` from `.env`. Other useful commands:

```bash
make migrate-down       # roll back the latest migration
make new-migration name=add_something
make sqlc               # regenerate db/sqlc from db/query
```

### 4. Run the API

```bash
go run .
```

Open <http://localhost:8080>. You will be redirected to the sign-in page. Use **Create an account** to register, then sign in.

The API listens on `PORT` (default `8080`). Health check: `GET /health`.

To send a test reminder email:

```bash
make test-email
```

To run the reminder worker locally:

```bash
make run-reminder-worker
```

### 5. Run the tests

```bash
go test ./...
```

Integration tests are skipped unless `TEST_DATABASE_URL` is set. They apply migrations and **truncate tables**, so always point them at a dedicated test database, never at development or production data.

```bash
TEST_DATABASE_URL=postgresql://postgres:password@localhost:5432/renewly_test?sslmode=disable go test ./integration -v
```

---

## Configuration reference

| Variable | Required | Description |
| --- | --- | --- |
| `DATABASE_URL` | Yes | PostgreSQL connection string. |
| `TEST_DATABASE_URL` | No | Separate database for integration tests. Tests skip when unset. |
| `JWT_SECRET` | Yes | HS256 signing secret for browser session JWTs and CSRF HMACs. Use at least 32 random bytes. |
| `OAUTH_GLOBAL_SECRET` | Yes for OAuth/MCP | At least 32 bytes, stable across restarts. Used by Fosite and consent CSRF. |
| `OAUTH_ISSUER` | Yes for OAuth/MCP | Public base URL of this service, for example `https://renewly.example.com`. No trailing slash required. The MCP resource becomes `<issuer>/mcp`. |
| `COOKIE_SECURE` | Recommended | Set to `true` in production (HTTPS). Use `false` only for local HTTP development. |
| `PORT` | No | API port. Default `8080`. |
| `DB_POOL_MAX_CONNS` | No | Maximum PostgreSQL pool connections. Default `5`. |
| `DB_POOL_MIN_CONNS` | No | Minimum pool connections. Default `0`. |
| `RESEND_API_KEY` | Worker only | Resend API key. |
| `EMAIL_FROM` | Worker only | Verified sender, for example `Renewly <renewly@example.com>`. |
| `RESEND_TEST_TO` | Optional | Recipient for `make test-email`. |
| `REMINDER_TIMEZONE` | No | Timezone used by the worker. Default `Asia/Kolkata`. |
| `REMINDER_BATCH_SIZE` | No | Batch size, 1–500. Default `100`. |
| `REMINDER_MAX_ATTEMPTS` | No | Retry attempts, 1–10. Default `5`. |
| `REMINDER_TEST_TO` | No | Redirect all reminder emails to this address. **Do not set in production.** |

---

## Sign-in and account flow

| Route | Method | Description |
| --- | --- | --- |
| `/` | GET | Redirects to `/auth/status` if signed in, otherwise `/auth/login`. |
| `/auth/register` | GET | Registration page. |
| `/auth/register` | POST | Create an account and sign in. |
| `/auth/login` | GET | Sign-in page. |
| `/auth/login` | POST | Sign in and set the `auth_token` cookie. |
| `/auth/status` | GET | Account page for the signed-in user. |
| `/auth/logout` | POST | Clear the browser session cookie. Requires a CSRF token. |
| `/api/register` | POST | JSON registration endpoint. |
| `/api/login` | POST | JSON login endpoint; sets the `auth_token` cookie. |
| `/api/logout` | POST | Clears the browser cookie. |

Passwords must be 6–72 characters. The browser pages enforce CSRF protection; the OAuth consent screen uses a separate signed, time-limited consent token.

When an MCP client starts authorization, Renewly stores the original OAuth request server-side and redirects the browser to sign in. After login, the browser resumes the exact authorization request. The client's redirect URI, scopes, state, PKCE challenge, and resource are never trusted from the consent POST body.

---

## Connecting Claude

Renewly is designed for MCP clients that support **remote MCP servers with OAuth**. Claude opens a browser window, the user signs in to Renewly, reviews the consent screen, and approves access. No API key or client secret needs to be copied into Claude.

> Use the **MCP server URL** from the section at the top of this README.

### Before you connect

1. Deploy Renewly behind a public **HTTPS** URL.
2. Set `OAUTH_ISSUER` to that exact public base URL, for example `https://renewly.example.com`.
3. Set `COOKIE_SECURE=true`.
4. Confirm the discovery documents are reachable:
   - `https://YOUR_HOST/.well-known/oauth-authorization-server`
   - `https://YOUR_HOST/.well-known/oauth-protected-resource/mcp`
5. Confirm the MCP endpoint responds with a `401` and a `WWW-Authenticate` header when called without a token.

### Claude web / Claude Desktop (remote MCP)

In Claude's custom connector settings, add a new remote MCP server and enter:

```text
https://YOUR_HOST/mcp
```

Then complete the browser flow:

1. Claude discovers the OAuth metadata.
2. Claude registers itself dynamically with Renewly.
3. A browser opens the Renewly sign-in page.
4. Sign in or create an account.
5. Review the consent screen. It lists read and write permissions, plus optional offline access.
6. Click **Allow access**.
7. Claude receives an access token and can call the Renewly tools.

If the connection later expires, Claude refreshes the access token using the refresh token. If the grant is revoked, reconnect through the same flow.

### Claude Desktop / Claude Code configuration

Clients that accept a remote HTTP MCP server can use:

```json
{
  "mcpServers": {
    "renewly": {
      "type": "http",
      "url": "https://YOUR_HOST/mcp"
    }
  }
}
```

For Claude Code:

```bash
claude mcp add --transport http renewly https://YOUR_HOST/mcp
```

For clients that do not support remote MCP URLs directly, bridge through `mcp-remote`:

```bash
npx -y mcp-remote https://YOUR_HOST/mcp
```

The exact configuration format depends on the Claude client version. The important part is the URL: **`https://YOUR_HOST/mcp`**.

### What Claude can do

Once connected, Claude can list subscriptions, inspect one subscription, find upcoming bills, create subscriptions, update subscriptions, and cancel subscriptions. All operations are limited to the account that approved the consent screen.

---

## Connecting a custom MCP client

A custom client must support MCP over streamable HTTP and OAuth 2.1 with PKCE. The discovery documents describe everything the client needs.

### 1. Discover the authorization server

```bash
curl https://YOUR_HOST/.well-known/oauth-authorization-server
```

Important values:

```json
{
  "issuer": "https://YOUR_HOST",
  "authorization_endpoint": "https://YOUR_HOST/oauth/authorize",
  "token_endpoint": "https://YOUR_HOST/oauth/token",
  "registration_endpoint": "https://YOUR_HOST/oauth/register",
  "revocation_endpoint": "https://YOUR_HOST/oauth/revoke",
  "code_challenge_methods_supported": ["S256"]
}
```

### 2. Register the client

Public clients only, with `token_endpoint_auth_method: "none"`. Redirect URIs must be HTTPS, or loopback HTTP for native clients (`localhost`, `127.0.0.1`, `::1`).

```bash
curl -X POST https://YOUR_HOST/oauth/register \
  -H 'Content-Type: application/json' \
  -d '{
    "client_name": "My MCP Client",
    "redirect_uris": ["http://127.0.0.1:8765/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none"
  }'
```

The response contains a `client_id`. Store it in your client configuration.

### 3. Start authorization with PKCE

Build a `code_verifier`, derive its S256 `code_challenge`, and open:

```text
https://YOUR_HOST/oauth/authorize
  ?client_id=YOUR_CLIENT_ID
  &response_type=code
  &redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcallback
  &scope=renewly%20offline_access
  &state=RANDOM_STATE
  &code_challenge=BASE64URL_SHA256_VERIFIER
  &code_challenge_method=S256
  &resource=https%3A%2F%2FYOUR_HOST%2Fmcp
```

The user signs in and approves the consent screen. The browser redirects to your callback with `code` and `state`.

### 4. Exchange the code

```bash
curl -X POST https://YOUR_HOST/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d grant_type=authorization_code \
  -d client_id=YOUR_CLIENT_ID \
  -d code=AUTHORIZATION_CODE \
  -d redirect_uri=http://127.0.0.1:8765/callback \
  -d code_verifier=YOUR_CODE_VERIFIER
```

The response contains `access_token`, `refresh_token`, `expires_in`, `scope`, and `token_type`.

### 5. Call the MCP endpoint

```bash
curl -X POST https://YOUR_HOST/mcp \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list",
    "params": {}
  }'
```

Call a tool:

```bash
curl -X POST https://YOUR_HOST/mcp \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "list_subscriptions",
      "arguments": {}
    }
  }'
```

### Refresh a token

```bash
curl -X POST https://YOUR_HOST/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d grant_type=refresh_token \
  -d client_id=YOUR_CLIENT_ID \
  -d refresh_token=YOUR_REFRESH_TOKEN
```

### Revoke a token

```bash
curl -X POST https://YOUR_HOST/oauth/revoke \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d client_id=YOUR_CLIENT_ID \
  -d token=YOUR_TOKEN
```

---

## MCP tools

All tools are scoped to the authenticated user. A user ID is never accepted from the AI client as a tool argument.

| Tool | Access | Description |
| --- | --- | --- |
| `list_subscriptions` | Read | List active subscriptions for the signed-in user. |
| `get_subscription` | Read | Get one subscription by ID. |
| `get_upcoming_bills` | Read | List active subscriptions renewing within `days_ahead` (1–365). |
| `create_subscription` | Write | Create a subscription. Amount is a decimal string; dates use `YYYY-MM-DD`. |
| `update_subscription` | Write | Update an existing subscription. |
| `cancel_subscription` | Write | Set a subscription's status to `cancelled`. |

The OAuth scope `renewly` covers these tools. The `offline_access` scope lets an MCP client refresh access without asking the user to sign in again.

---

## REST API

The REST API uses the `auth_token` cookie for authentication. Send it as a cookie after `POST /api/login`.

| Route | Method | Auth | Description |
| --- | --- | --- | --- |
| `/health` | GET | No | Health check. |
| `/api/register` | POST | No | Register a user. |
| `/api/login` | POST | No | Sign in and receive the session cookie. |
| `/api/logout` | POST | No | Clear the session cookie. |
| `/api/subscriptions` | GET | Cookie | List the user's active subscriptions. |
| `/api/subscriptions` | POST | Cookie | Create a subscription. |
| `/api/subscriptions/:id` | PUT | Cookie | Update one subscription. |

### Register

```bash
curl -X POST http://localhost:8080/api/register \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Vijay",
    "email": "vijay@example.com",
    "password": "password123"
  }'
```

### Login

```bash
curl -c cookies.txt -X POST http://localhost:8080/api/login \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "vijay@example.com",
    "password": "password123"
  }'
```

### Create a subscription

```bash
curl -b cookies.txt -X POST http://localhost:8080/api/subscriptions \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Netflix",
    "category": "Entertainment",
    "amount": 649.00,
    "currency": "INR",
    "billing_cycle": "monthly",
    "auto_renew": true,
    "start_date": "2026-11-01",
    "next_billing_date": "2026-12-01",
    "website": "https://netflix.com",
    "notes": "Family plan"
  }'
```

### List subscriptions

```bash
curl -b cookies.txt http://localhost:8080/api/subscriptions
```

### Update a subscription

```bash
curl -b cookies.txt -X PUT http://localhost:8080/api/subscriptions/1 \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Netflix Premium",
    "category": "Entertainment",
    "amount": 799.00,
    "currency": "INR",
    "billing_cycle": "monthly",
    "auto_renew": true,
    "start_date": "2026-11-01",
    "next_billing_date": "2026-12-01"
  }'
```

`billing_cycle` is `monthly` or `yearly`. `amount` must be a positive decimal.

---

## Deployment

The repository includes a `Dockerfile` and a `cloudbuild.yaml` that builds one image and uses it for both the API service and the reminder job.

### Build and run with Docker

```bash
docker build -t renewly .
docker run --rm --env-file .env -p 8080:8080 renewly
```

The image runs as a non-root user and listens on port `8080`.

### Google Cloud Run

The included Cloud Build pipeline:

1. Runs `go test ./...`.
2. Builds and pushes the image to Artifact Registry.
3. Deploys the `renewly-api` Cloud Run service.
4. Deploys or updates the `renewly-reminder-worker` Cloud Run Job.

Secrets are read from Secret Manager:

- `renewly-database-url`
- `renewly-jwt-secret`
- `oauth-global-secret`
- `renewly-resend-api-key`

Before deploying:

- Set `OAUTH_ISSUER` to the public Cloud Run URL (or custom domain). It must match the URL clients use.
- Keep `COOKIE_SECURE=true`.
- Run database migrations against the production database.
- Create a Cloud Scheduler trigger for the reminder job (for example, daily).
- Restrict IAM for the runtime service account to the minimum required permissions.

The Cloud Run service uses `--allow-unauthenticated` because MCP clients must reach the OAuth and MCP endpoints publicly. Authorization is enforced by OAuth bearer tokens, not by Cloud Run IAM.

---

## Security

### Implemented controls

- bcrypt password hashing.
- HS256 JWTs with 24-hour expiry, stored in `HttpOnly` cookies with `SameSite=Lax`.
- `Secure` cookies when `COOKIE_SECURE=true`.
- CSRF protection on registration, login, logout, and consent forms.
- OAuth 2.1 authorization code flow with mandatory PKCE S256.
- Single-use, server-side OAuth authorization continuations.
- Exact audience validation for MCP tokens: the client and the granted token audience must both match `<OAUTH_ISSUER>/mcp`.
- No browser cookie accepted as an MCP credential.
- Per-user data access enforced in SQL and in MCP tool handlers.
- Parameterized SQL through pgx/sqlc.
- Escaped HTML templates with CSP, `X-Frame-Options: DENY`, `nosniff`, and `no-referrer` headers.
- Request body limits on registration, login, consent, and client registration.
- Redirect URI validation: HTTPS, or loopback HTTP for native clients.
- OAuth token signatures stored in PostgreSQL; raw bearer tokens are not persisted.
- Non-root Docker runtime image.
- Production secrets loaded from Google Secret Manager.

### Hardening recommendations

- Add rate limiting to `/auth/login`, `/api/login`, `/api/register`, and `/oauth/register`. Open dynamic client registration is convenient but can be spammed.
- Add email verification and password reset.
- Consider MFA for account access.
- Remove the `MCP DEBUG` log lines in `oauth/server.go` before high-traffic production use.
- Consider shortening or rotating JWT session lifetime, and add server-side session revocation if immediate logout everywhere is required.
- Add a token-management page so users can list and revoke MCP grants.
- Run dependency vulnerability scanning (for example `govulncheck`) in CI.
- Review Cloud Run IAM and Secret Manager access for least privilege.

### Reporting a vulnerability

Please do not open a public issue for a security problem. Contact the repository owner privately with reproduction steps and affected versions.

---

## Troubleshooting

### Claude cannot connect

- The MCP URL must be public **HTTPS** and end with `/mcp`.
- `OAUTH_ISSUER` must exactly match the public base URL used by clients.
- Check `https://YOUR_HOST/.well-known/oauth-authorization-server` and `https://YOUR_HOST/.well-known/oauth-protected-resource/mcp`.
- Check that `https://YOUR_HOST/mcp` returns `401` with a `WWW-Authenticate` header when called without a token.
- Make sure the server clock is correct. OAuth timestamps and JWTs are time-sensitive.

### `invalid_token` from `/mcp`

- The access token may be expired or revoked. Reconnect the client.
- The token audience must be `<OAUTH_ISSUER>/mcp`. If you changed `OAUTH_ISSUER`, previously issued tokens are no longer valid.
- The registered client's audience must also include `<OAUTH_ISSUER>/mcp`.

### Sign-in loops or the cookie is not saved

- If using plain HTTP locally, set `COOKIE_SECURE=false`.
- In production over HTTPS, set `COOKIE_SECURE=true`.
- Make sure your reverse proxy forwards the original protocol and host correctly.

### `OAUTH_GLOBAL_SECRET must contain at least 32 bytes`

Generate a longer value:

```bash
openssl rand -hex 32
```

Changing this value invalidates existing OAuth sessions and consent tokens.

### `JWT_SECRET is not configured`

Set `JWT_SECRET` in `.env` or in the process environment. The API will reject cookie authentication without it.

### Email reminders are not sent

- Check `RESEND_API_KEY`, `EMAIL_FROM`, and that the sender domain is verified in Resend.
- If `REMINDER_TEST_TO` is set, all reminders go to that address. Remove it in production.
- Run `make test-email` to isolate Resend configuration.
- Check the worker logs and the `subscription_reminders.last_error` column.

### Listing subscriptions returns an error when there are none

The current service maps an empty result to an error, so `GET /api/subscriptions` may return `500` for a user with no active subscriptions. This is a known functional bug, not a security issue.

---

## Known limitations

- No rate limiting.
- No email verification, password reset, or MFA.
- No server-side revocation of browser JWTs; sign-out clears the cookie only.
- OAuth grants remain valid until the client revokes them or the user revokes them through the token endpoint.
- No UI for managing connected applications.
- Minimum password length is 6 characters.
- No license file is included yet.
- Integration tests truncate tables; use a dedicated test database.
- Debug logging remains in the MCP authentication path.

---

## License

No license has been specified for this project yet.
