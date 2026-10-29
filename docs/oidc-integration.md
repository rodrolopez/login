# OpenID Connect integration

The Identity API is an OpenID Connect Provider (OP). Local development issuer:

```text
http://127.0.0.1:3005/oidc
```

Discovery metadata is available at `/.well-known/openid-configuration` relative to the issuer. Obtain the `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `userinfo_endpoint`, and `end_session_endpoint` from discovery instead of hardcoding protocol endpoints in a production client.

## Registered clients

| Client ID                           | Type             | Redirect URI                     | Token authentication  | PKCE             |
| ----------------------------------- | ---------------- | -------------------------------- | --------------------- | ---------------- |
| `identity-public-test-client`       | Public           | `http://127.0.0.1:4100/callback` | `none`                | Required, `S256` |
| `identity-confidential-test-client` | Confidential     | `http://127.0.0.1:4200/callback` | `client_secret_basic` | Required, `S256` |
| `bff-reference-client`              | Confidential BFF | `http://127.0.0.1:4300/callback` | `client_secret_basic` | Required, `S256` |

The BFF client can request `openid email offline_access`. Its development secret is supplied through ignored local configuration (`OIDC_BFF_CLIENT_SECRET`); generate a fresh value locally, never copy one from documentation or source control. Development clients are not production registrations. Production clients are loaded from secret-managed `OIDC_CLIENTS` configuration.

## Authorization Code with PKCE

1. Discover the issuer metadata and validate that its `issuer` exactly matches the configured issuer.
2. Generate high-entropy `state`, `nonce`, and PKCE `code_verifier`; derive the `S256` challenge. Keep the verifier and nonce server-side.
3. Redirect the user agent to the discovered authorization endpoint with `client_id`, exact registered `redirect_uri`, `response_type=code`, requested scope, `state`, `nonce`, `code_challenge`, and `code_challenge_method=S256`.
4. The provider creates a login interaction at `/oidc/interaction/:uid`. The interaction endpoint returns a JSON prompt. The integrating application presents its own login UI and completes the interaction using `POST /auth/login` with `interactionUid`. It must preserve the provider's HttpOnly interaction cookies. When the account has MFA enabled, login returns `202` with `challengeId`; complete it at `POST /auth/mfa/totp/verify` with a TOTP or recovery code before expecting an authorization redirect.
5. If consent is requested, show the requested scopes to the user and submit `{ "approve": true }` to `POST /oidc/interaction/:uid/consent`. Do not approve scopes the user has not accepted.
6. At the registered redirect URI, validate the response `state`, then exchange the authorization code at the discovered token endpoint using the same redirect URI, the PKCE verifier, and the client's configured authentication method. Confidential clients authenticate with HTTP Basic. Never put a client secret in a browser application.
7. Validate ID tokens using a maintained OIDC library: verify the signature against the discovered JWKS, exact issuer, audience/client ID, expiration, nonce, and applicable authorized-party claims. Do not treat a decoded but unverified JWT as authenticated identity.

This provider supports only the Authorization Code response type. PKCE `S256` is mandatory. It does not expose implicit or hybrid flows. Discovery advertises `openid`, `email`, and `offline_access`; ID tokens use RS256.

## Claims and UserInfo

The supported claims are `sub`, `email`, `email_verified`, `sid`, `auth_time`, and `iss`. The `/me` UserInfo endpoint requires a valid access token in the Authorization header. Use a maintained OIDC client library to validate the UserInfo subject against the authenticated ID token subject.

## Refresh and logout

Clients requesting `offline_access` may receive a refresh token. Refresh tokens are rotated on use and bound to the provider session; persist the latest value server-side and discard the old value immediately. Access and ID tokens are short-lived. Account disablement, suspension, anonymization, password recovery, and provider logout invalidate associated sessions, refresh tokens, and grants according to the relevant account lifecycle operation.

For RP-Initiated Logout, obtain the `end_session_endpoint` from discovery and redirect the user agent with `id_token_hint`, a registered `post_logout_redirect_uri`, and an unpredictable logout `state`. The provider may show a confirmation page; the browser must submit its confirmation form. Validate returned logout state before completing the client-side logout.

## Local test guidance

Use only the registered development clients and synthetic accounts. Start PostgreSQL/Redis and the API, then use an OIDC library's discovery and authorization-code APIs. Do not commit JWKS private material, client secrets, authorization codes, access/refresh tokens, cookies, or copied browser credentials. See [the BFF example](./bff-integration.md) for a runnable server-side client.
