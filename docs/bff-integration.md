# Reference Backend-for-Frontend integration

The runnable example in [`examples/bff-client`](../examples/bff-client/README.md) demonstrates a server-side web client. It uses the registered confidential client ID `bff-reference-client`, Authorization Code with PKCE `S256`, server-side state/nonce validation, MFA and consent prompts, UserInfo, refresh-token rotation, and RP-Initiated Logout.

## Local setup

1. Start local PostgreSQL and Redis, apply migrations, and start the Identity API using Node 24.
2. Create a local BFF client secret and place it only in the ignored root `.env` file as `OIDC_BFF_CLIENT_SECRET`. Use at least 32 random bytes, for example by generating a value with `openssl rand -base64 48`. The provider reads it during startup; restart the API after changing it.
3. Start the reference BFF from the repository root:

   ```sh
   npm run bff:dev
   ```

4. Open `http://127.0.0.1:4300`, choose **Sign in**, and use an active account with a verified primary email. The BFF presents the local login, MFA, and consent prompts required by the Identity API's interaction contract.
5. After authorization, `/protected` calls the provider's UserInfo endpoint and returns only the subject and approved email claims. Choose **Sign out** to clear the local BFF session and start RP-Initiated Logout at the provider.

The API and BFF must use the same `OIDC_ISSUER` and local issuer host. The included redirect URI is `http://127.0.0.1:4300/callback`; do not substitute `localhost` for `127.0.0.1` unless you also register the exact alternative URI and align cookie hosts.

## Session and token handling

The browser receives only a random opaque `bff_session` cookie. It is HttpOnly, SameSite=Lax, scoped to `/`, and gains Secure when the BFF base URL uses HTTPS. The BFF stores only a SHA-256 digest of the cookie identifier as the session-map key; access, ID, and refresh tokens remain server-side and are never included in HTML, JSON, URLs, or browser storage. The protected resource calls UserInfo with the server-held access token and validates the returned subject against the ID token subject.

The example stores sessions and in-progress login transactions in process memory. Restarting it logs users out and invalidates unfinished transactions. This is deliberately a single-process local demonstration. A deployed BFF needs a shared, access-controlled session store, secure token-at-rest handling, key rotation, TLS, monitoring, and operational recovery. Do not expose the example directly to the internet.

The login form sends credentials only from the BFF to the Identity API's login endpoint over the configured local connection; the BFF does not persist or log passwords. TOTP and one-time recovery codes are forwarded to the MFA verification endpoint and never stored in the BFF session. Login state is bound to an HttpOnly SameSite cookie. Logout forms require a session-bound CSRF value.

## Logout behavior

The BFF deletes its local session and clears its cookie before redirecting to the provider's discovered end-session endpoint with `id_token_hint`, the registered post-logout URI, and a one-time `state`. The provider's current development configuration presents a confirmation page. After the user confirms, the provider revokes session-bound grants/tokens and redirects to `/logout/callback`; the BFF validates the logout state and confirms local logout. A production client should keep this confirmation and state validation behavior, and must not rely on local cookie deletion alone to revoke provider grants.

## Source and commands

The example source is [`server.ts`](./../examples/bff-client/server.ts). Start the API with `npm run dev` and start the client with `npm run bff:dev`. The integration suite exercises PKCE, login interaction, consent, code exchange, protected UserInfo, token isolation from the browser, and local logout without making calls to external identity providers.
