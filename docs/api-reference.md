# Identity API reference

This document describes the application-owned HTTP routes. OpenID Connect protocol endpoints are documented separately in [OIDC integration](./oidc-integration.md).

## Conventions

- Local base URL: `http://127.0.0.1:3005`.
- JSON requests use `Content-Type: application/json`.
- Authentication uses the opaque `identity_session` cookie returned by the API. Send it with `curl -b COOKIE_JAR`; do not manufacture it or send a user ID as authentication.
- Cookies are `HttpOnly` and `SameSite=Lax`; `Secure` is enabled in production.
- Responses are `Cache-Control: no-store`. Errors do not include stack traces or internal details.
- `Accept-Language: es` or `Accept-Language: en` selects supported validation and authentication messages.
- Payloads are strictly validated. Unknown fields are rejected on authentication and MFA endpoints.

## Health

### `GET /health`

No authorization required.

| Status | Response                                        |
| ------ | ----------------------------------------------- |
| `200`  | `{ "status": "ok", "service": "identity-api" }` |

## Registration and local login

### `POST /auth/register`

Creates a pending local account and requests primary email verification.

```json
{ "email": "person@example.test", "password": "at least 12 characters" }
```

| Status | Response                                  |
| ------ | ----------------------------------------- |
| `201`  | `{ "userId": "<uuid>" }`                  |
| `400`  | Invalid or malformed payload              |
| `409`  | Email already registered                  |
| `429`  | Rate limit reached; inspect `Retry-After` |
| `503`  | Infrastructure unavailable                |

Registration does not issue a session. Email delivery is disabled by default; verification links are not delivered until an email adapter is configured.

### `POST /auth/login`

```json
{ "email": "person@example.test", "password": "the account password" }
```

An OIDC login interaction may include `interactionUid`:

```json
{
  "email": "person@example.test",
  "password": "the account password",
  "interactionUid": "<interaction-uid>"
}
```

| Status      | Response                                                                                                    |
| ----------- | ----------------------------------------------------------------------------------------------------------- |
| `200`       | Local login: `{ "userId": "<uuid>" }` and `identity_session` cookie                                         |
| `202`       | MFA required: `{ "mfaRequired": true, "challengeId": "<opaque-challenge>" }`; no complete session is issued |
| `302`/`303` | OIDC interaction completed; browser continues to the provider                                               |
| `400`       | Invalid payload or OIDC interaction                                                                         |
| `401`       | Generic invalid-credentials response                                                                        |
| `429`       | Rate limit reached; inspect `Retry-After`                                                                   |
| `503`       | Infrastructure unavailable                                                                                  |

Login requires an active account and verified primary email. Passwords are verified using Argon2id. Invalid-login responses do not disclose whether an account exists.

### `GET /auth/session`

Requires a valid `identity_session` cookie.

| Status | Response                                                         |
| ------ | ---------------------------------------------------------------- |
| `200`  | `{ "userId": "<uuid>" }`                                         |
| `401`  | Session missing, expired, revoked, or account no longer eligible |
| `503`  | Session infrastructure unavailable                               |

### `POST /auth/logout`

Revokes the current API session and clears its cookie. No JSON payload is required.

| Status | Response                      |
| ------ | ----------------------------- |
| `204`  | Session ended                 |
| `503`  | Logout could not be completed |

## TOTP MFA

All enrollment endpoints require an authenticated API session. Login verification uses a short-lived `challengeId`, not an existing session cookie.

### `POST /auth/mfa/totp/enrollment`

Starts enrollment; the secret is returned once so a user interface can render a QR code.

| Status | Response                                                              |
| ------ | --------------------------------------------------------------------- |
| `200`  | `{ "secret": "<base32-secret>", "otpauthUri": "otpauth://totp/..." }` |
| `401`  | No valid API session                                                  |
| `409`  | TOTP is already enabled                                               |
| `503`  | Missing MFA encryption key or infrastructure unavailable              |

### `POST /auth/mfa/totp/confirm`

Confirms enrollment with the first six-digit time-based code.

```json
{ "token": "<six-digit-totp>" }
```

| Status | Response                                               |
| ------ | ------------------------------------------------------ |
| `200`  | `{ "recoveryCodes": ["<one-time-code>", "..."] }`      |
| `400`  | Malformed or invalid TOTP                              |
| `401`  | No valid API session                                   |
| `429`  | Too many confirmation attempts                         |
| `503`  | Encryption configuration or infrastructure unavailable |

Recovery codes are displayed once. Store them securely; each is single-use.

### `POST /auth/mfa/totp/verify`

Completes an MFA login challenge with exactly one factor:

```json
{ "challengeId": "<opaque-challenge>", "token": "<six-digit-totp>" }
```

or

```json
{ "challengeId": "<opaque-challenge>", "recoveryCode": "<one-time-recovery-code>" }
```

| Status      | Response                                                               |
| ----------- | ---------------------------------------------------------------------- |
| `200`       | Local login completed: `{ "userId": "<uuid>" }` and API session cookie |
| `302`/`303` | OIDC login interaction completed                                       |
| `400`       | Malformed payload or invalid OIDC interaction                          |
| `401`       | Invalid/expired challenge or invalid/consumed factor                   |
| `429`       | Too many factor attempts                                               |
| `503`       | MFA or session infrastructure unavailable                              |

The challenge expires after five minutes and is single-use. Attempts are rate-limited in Redis.

## Email verification and password recovery

Request endpoints deliberately return the same generic response for existing and unknown email addresses.

### `POST /auth/email/verification/request`

```json
{ "email": "person@example.test" }
```

| Status | Response                  |
| ------ | ------------------------- |
| `202`  | Generic accepted response |
| `400`  | Invalid payload           |

### `POST /auth/email/verification/confirm`

```json
{ "token": "<single-use-verification-token>" }
```

| Status | Response                                           |
| ------ | -------------------------------------------------- |
| `200`  | Email verified                                     |
| `400`  | Invalid, expired, consumed, or wrong-purpose token |
| `503`  | Infrastructure unavailable                         |

### `POST /auth/password/recovery/request`

```json
{ "email": "person@example.test" }
```

| Status | Response                                                 |
| ------ | -------------------------------------------------------- |
| `202`  | Same generic response for existing and unknown addresses |
| `400`  | Invalid payload                                          |

### `POST /auth/password/recovery/confirm`

```json
{ "token": "<single-use-recovery-token>", "password": "at least 12 characters" }
```

| Status | Response                                                                  |
| ------ | ------------------------------------------------------------------------- |
| `200`  | Password reset completed; active API/OIDC sessions and grants are revoked |
| `400`  | Invalid, expired, consumed, or wrong-purpose token / invalid password     |
| `503`  | Infrastructure unavailable                                                |

Email delivery uses a disabled adapter by default. It records only suppression metadata in logs and discards token text. A real provider is not configured by this API reference.

## Google sign-in

Google OAuth routes are available only when all Google settings are configured.

### `GET /auth/google`

Starts the Google Authorization Code flow with `state`, `nonce`, and PKCE. Responds with `302` to Google and sets a short-lived HttpOnly state cookie.

### `GET /auth/google/callback`

Google redirects here with authorization parameters. A successful login returns `{ "userId": "<uuid>" }` and an API session cookie (`200`), or returns `202` with an MFA challenge. Invalid state, callback, or provider response returns a generic error.

Google email equality never automatically links an existing local-password account.

## Organizations and authorization

All organization routes require a valid `identity_session`. Authorization is checked against current membership and role data on every request. Client-supplied roles never grant access.

### `POST /organizations`

Creates an organization and owner membership for the authenticated user.

```json
{ "name": "Example workspace", "slug": "example-workspace" }
```

| Status | Response                                                                |
| ------ | ----------------------------------------------------------------------- |
| `201`  | Organization object with `id`, `name`, `slug`, `status`, and timestamps |
| `400`  | Invalid organization payload                                            |
| `401`  | No valid API session                                                    |
| `409`  | Slug already in use                                                     |
| `503`  | Organization service unavailable                                        |

### `GET /organizations/:organizationId/resources`

Requires an active membership with `resources.read` in this organization.

| Status | Response                                                                     |
| ------ | ---------------------------------------------------------------------------- |
| `200`  | `{ "organizationId": "<uuid>", "organizationName": "...", "resources": [] }` |
| `401`  | No valid API session                                                         |
| `403`  | User lacks active membership or permission                                   |
| `404`  | Malformed or unknown organization ID                                         |

### `GET /organizations/:organizationId/audit`

Requires active `members.read` permission. Returns non-sensitive audit events.

| Status | Response                                   |
| ------ | ------------------------------------------ |
| `200`  | `{ "events": [...] }`                      |
| `401`  | No valid API session                       |
| `403`  | User lacks active membership or permission |
| `404`  | Malformed or unknown organization ID       |

### `POST /organizations/:organizationId/members`

Requires organization owner/admin permission. Adds an existing global user.

```json
{ "userId": "<uuid>", "role": "member" }
```

Allowed added roles: `admin`, `member`. The owner role is assigned during organization creation.

| Status | Response                                                                                                                          |
| ------ | --------------------------------------------------------------------------------------------------------------------------------- |
| `201`  | `{ "membership": { "id": "<uuid>", "organizationId": "<uuid>", "userId": "<uuid>", "role": "member", "status": "active", ... } }` |
| `400`  | Invalid membership payload                                                                                                        |
| `401`  | No valid API session                                                                                                              |
| `403`  | Actor lacks permission                                                                                                            |
| `409`  | Membership cannot be created in its current state                                                                                 |

### `PATCH /organizations/:organizationId/members/:memberUserId/role`

Requires owner/admin permission.

```json
{ "role": "admin" }
```

| Status | Response                                          |
| ------ | ------------------------------------------------- |
| `200`  | `{ "membership": { ... } }`                       |
| `400`  | Invalid role                                      |
| `401`  | No valid API session                              |
| `403`  | Actor lacks permission                            |
| `404`  | Invalid membership identifier                     |
| `409`  | Membership cannot be changed in its current state |

### `PATCH /organizations/:organizationId/members/:memberUserId/status`

Requires owner/admin permission.

```json
{ "status": "disabled" }
```

Allowed values are `suspended`, `disabled`, and `revoked`.

| Status | Response                                          |
| ------ | ------------------------------------------------- |
| `200`  | `{ "membership": { ... } }`                       |
| `400`  | Invalid membership status                         |
| `401`  | No valid API session                              |
| `403`  | Actor lacks permission                            |
| `404`  | Invalid membership identifier                     |
| `409`  | Membership cannot be changed in its current state |

Disabled or revoked membership loses authorization on the next request, even if the global account remains active.
