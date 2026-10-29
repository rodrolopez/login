# Identity API

Backend base for the central identity service. See [LOGIN.md](./LOGIN.md) for the project requirements and [ADR 0001](./docs/decisions/0001-arquitectura-inicial.md) for the Phase 0 decisions.

## Requirements

- Node.js 24 LTS
- npm 11 or newer

## Install and run

```sh
npm ci
npm run dev
```

The API listens on port `3005` by default. Its health endpoint is `GET http://localhost:3005/health`.

## PostgreSQL and Redis

Copy `.env.example` to `.env` and replace the local password placeholders before starting the services. Set `PGPASSWORD` to the same local value as `POSTGRES_PASSWORD`; use separate values for Redis and test services:

```sh
cp .env.example .env
# Replace the password placeholders in .env before starting services.
docker compose up -d --wait postgres redis
npm run db:migrate
npm run dev
```

The default Compose profile exposes PostgreSQL 18 on `127.0.0.1:5436` and Redis 7 on loopback only. PostgreSQL listens on port 5432 inside its container; Compose maps host port 5436 to it. Development data is persisted in local Docker volumes. The application reads PG and Redis connection settings from `.env`; it checks both services during startup and exits with a generic message if configuration or infrastructure is unavailable. It retries PostgreSQL startup queries with bounded backoff and uses ioredis reconnects with a capped delay. Connection errors are logged without driver messages or credentials.

`CORS_ALLOWED_ORIGINS` optionally lists exact browser origins separated by commas, without paths or wildcards. Production entries must use HTTPS. API CORS does not reflect arbitrary origins; credentials are allowed only for the configured list or the request's same origin. The OIDC provider keeps unauthenticated discovery/JWKS readable and restricts client-specific CORS to registered redirect origins. HTTP security headers include a restrictive API CSP, frame and MIME protections, and HSTS in production.

Migrations are explicit operator commands and are never run by API startup. `npm run db:migrate` creates `public.schema_migrations`, serializes concurrent runs with a PostgreSQL advisory lock, verifies checksums of applied files, and applies each pending migration in its own transaction. Review and back up production data before running migrations in production.

Integration tests never fall back to application database settings. They require explicit `TEST_*` settings, a loopback PostgreSQL host with a database name ending in `_test`, and Redis database index 15. The Compose `test-infra` profile uses a separate temporary PostgreSQL data directory and in-memory Redis service on ports 15433 and 16380:

```sh
docker compose --profile test-infra up -d --wait postgres-test redis-test
npm test
docker compose --profile test-infra down
```

That profile's database is disposable and separate from the development volume. Do not point `TEST_*` settings at production or shared databases. CI uses isolated PostgreSQL 18 and Redis service containers with synthetic test credentials.

## Global identity data model

Migrations `0002_create_global_identity_tables.sql` and `0003_argon2id_phc_parameters.sql` add users, emails, Argon2id password credential records and external identity links, then validate the PHC parameter order emitted by the Argon2 library. Apply migrations explicitly with `npm run db:migrate`; the API does not migrate on startup. Account deactivation, anonymization and physical deletion are separate repository operations. See [ADR 0002](./docs/decisions/0002-identidad-global-y-privacidad.md) for the data and privacy decisions.

## Registration and login

`POST /auth/register` accepts `{ "email": "person@example.test", "password": "at least 12 characters" }`; `POST /auth/login` accepts the same fields and returns the account ID plus an opaque Redis-backed session cookie only after the primary email is verified. Registration creates a pending account and requests verification. Use `GET /auth/session` to validate the current API session and `POST /auth/logout` to revoke it. Passwords use Argon2id, and Redis enforces shared rate limits. Errors honor `Accept-Language` for English and Spanish. When login is called with an OIDC `interactionUid`, it completes the provider interaction and uses the OIDC session. See [ADR 0003](./docs/decisions/0003-registro-login-basico.md) and [ADR 0005](./docs/decisions/0005-sesiones-cookies-y-renovacion.md) for policies and limits.

## Email verification and password recovery

`POST /auth/email/verification/request` and `POST /auth/password/recovery/request` accept `{ "email": "person@example.test" }` and always return the same `202 Accepted` response for known and unknown addresses. Confirm with `POST /auth/email/verification/confirm` and `{ "token": "..." }`, or reset with `POST /auth/password/recovery/confirm` and `{ "token": "...", "password": "at least 12 characters" }`. Tokens are single-use, expire after 24 hours (verification) or 30 minutes (recovery), and only their SHA-256 representations are stored. Successful password recovery revokes API sessions, OIDC artifacts and grants. Email delivery is disabled by default; the default adapter logs only the suppressed purpose and discards the message. Tests inject an in-memory delivery adapter and never call an email service. See [ADR 0008](./docs/decisions/0008-correo-verificacion-recuperacion.md).

## OpenID Connect provider

The repository pins the Node.js major version in `.nvmrc`; run `nvm use` from this directory before starting the API. The provider is mounted at `http://127.0.0.1:3005/oidc`; discovery is available at `/oidc/.well-known/openid-configuration`. In development, requests made through `http://localhost:3005` are normalized to the configured issuer host. Other Host values are rejected so discovery and redirects remain bound to the static issuer. Discovery advertises only the Authorization Code response and grant. Apply the new schema before starting the API:

```sh
npm run db:migrate
npm run dev
```

The development issuer is static by default. The provider defines one public authorization-code client with PKCE required, one confidential test client, and the confidential `bff-reference-client` used by the local example. The BFF redirect URIs are `http://127.0.0.1:4300/callback` and `http://127.0.0.1:4300/logout/callback`. The provider exposes RP-Initiated Logout at `/oidc/session/end`; logout destroys its session and revokes session-bound grants and tokens. Only active accounts with a verified primary email can complete OIDC login. Development signing, cookie, and client secrets are generated at runtime when absent; restarts invalidate outstanding provider sessions and tokens. The BFF needs a stable secret in the ignored local `.env` as `OIDC_BFF_CLIENT_SECRET`; generate it with `openssl rand -base64 48`, then restart the API and BFF. Never use development-generated credentials in production.

See [API reference](./docs/api-reference.md), [OIDC integration guide](./docs/oidc-integration.md), and [BFF integration guide](./docs/bff-integration.md). Run the reference BFF from the repository root with `npm run bff:dev`; its source and local setup are in [`examples/bff-client`](./examples/bff-client/README.md).

For production startup, supply `OIDC_ISSUER`, `OIDC_CLIENTS` (JSON array of registered clients), `OIDC_CONFIDENTIAL_CLIENT_SECRET` only if those clients use it, `OIDC_COOKIE_KEYS`, and `OIDC_JWKS` through a secret manager. The service refuses to start in production when signing, cookie, or client configuration is missing. Dynamic client registration is disabled. The project still needs a production key rotation and client lifecycle process before deployment.

OIDC authorization codes, sessions, interactions and other short-lived models use Redis. OIDC grants (durable user consent) use the PostgreSQL `identity_api.oidc_grants` table. The interaction endpoint exposes the current login or consent prompt as JSON; login is completed through `POST /auth/login` with the returned `interactionUid`, and consent is explicitly submitted to `POST /oidc/interaction/:uid/consent` with `{ "approve": true }`. Only active accounts with a verified primary email can complete the flow. See [ADR 0004](./docs/decisions/0004-proveedor-oidc.md) and [ADR 0008](./docs/decisions/0008-correo-verificacion-recuperacion.md).

API session cookies and OIDC cookies are HttpOnly and SameSite=Lax; Secure is enabled when `NODE_ENV=production`. API sessions expire after eight hours. OIDC sessions expire after eight hours, access and ID tokens after ten minutes, and refresh tokens after fourteen days; refresh tokens rotate on every use and are bound to the OIDC session. Account status changes that disable, suspend, or anonymize an account must go through `IdentitySessionRevocationService` so API sessions, cached OIDC artifacts and durable grants are revoked. See [ADR 0005](./docs/decisions/0005-sesiones-cookies-y-renovacion.md).

## Google sign-in

Install dependencies with `npm ci`, then configure `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GOOGLE_REDIRECT_URI` in the ignored `.env` file. Register the exact callback URI in Google Cloud Console. For local development the example is `http://localhost:3005/auth/google/callback`; production callbacks must use HTTPS. Open `/auth/google` on the same host as the callback URI (`localhost` or `127.0.0.1`) to begin sign-in. Google returns to `GET /auth/google/callback`, which validates state, nonce, PKCE and the ID Token before issuing the standard API session cookie. The transient flow state expires after five minutes and can be consumed once.

Google identities are matched by the validated issuer and `sub`. A matching email alone never links to a local account; the callback reports that the user must first sign in with the local password. New accounts and their Google identity are persisted atomically. The temporary OAuth state is bound to a short-lived browser cookie as well as Redis. Tests inject a fake Google OIDC client and never call Google. See [ADR 0006](./docs/decisions/0006-integracion-google.md).

## TOTP multi-factor authentication

TOTP MFA is optional per account. Generate a dedicated 32-byte encryption key with `openssl rand -hex 32`, save it as `MFA_ENCRYPTION_KEY` in the ignored `.env`, and keep it stable and backed up; without that key the API cannot decrypt enrolled seeds. With a valid API session, call `POST /auth/mfa/totp/enrollment`; the response contains the secret and `otpauth://` URI for a QR code. Submit the first six-digit authenticator code to `POST /auth/mfa/totp/confirm`. This activates MFA and returns ten one-time recovery codes; show them once and ask the user to store them safely.

When MFA is enabled, a correct password to `POST /auth/login` or a valid Google sign-in returns `202` with `{ "mfaRequired": true, "challengeId": "..." }` and does not issue a session or finish an OIDC interaction. Complete it using `POST /auth/mfa/totp/verify` with `{ "challengeId": "...", "token": "123456" }` or `{ "challengeId": "...", "recoveryCode": "..." }`. Login challenges expire after five minutes and are single-use; TOTP verification and recovery-code attempts are limited by Redis. TOTP seeds are encrypted with AES-256-GCM in PostgreSQL; recovery codes are stored as Argon2id hashes. See [ADR 0009](./docs/decisions/0009-mfa-totp.md).

## Organizations and authorization

Run `npm run db:migrate` to apply migration `0005_create_organizations_and_authorization.sql`. An authenticated user creates an organization with `POST /organizations` and `{ "name": "Acme", "slug": "acme" }`; the API creates tenant-scoped `owner`, `admin`, and `member` roles and an active owner membership atomically. Owners and admins can add existing users with `POST /organizations/:organizationId/members` and `{ "userId": "...", "role": "member" }`. Role and membership changes are audited. `GET /organizations/:organizationId/resources` demonstrates tenant-protected resource access; it returns an empty collection until business resources are introduced. Membership status and role are checked in PostgreSQL on each request, so disabled, suspended, or revoked memberships lose access immediately. See [ADR 0007](./docs/decisions/0007-organizaciones-autorizacion.md).

## Quality checks

```sh
npm run format:check
npm run lint
npm run typecheck
npm test
npm run build
npm audit
```

The CI workflow runs these checks for pull requests and pushes. Keep `package-lock.json` committed and use `npm ci` for reproducible installs.

## Production preparation

The production artifacts are documented in [deployment](./docs/deployment.md), [operations](./docs/operations.md), and the [production checklist](./docs/production-checklist.md). `docker-compose.prod.yml` does not publish host ports; attach a reviewed reverse proxy to the edge network and place a CDN/WAF in front of it. PostgreSQL runtime access uses the `identity_app` role; use the distinct `identity_migrator` credential only for reviewed manual migrations. Configure OTLP/HTTP to a private collector and store all production secrets outside this repository.

Build the production image with Node 24 and Docker Compose. Provision the production database roles, run `npm run db:migrate:prod` as a deliberate operator action, then start the stack. The API startup never applies migrations.
