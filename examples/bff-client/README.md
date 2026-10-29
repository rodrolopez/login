# Reference BFF client

Run this local-only Express client from the repository root. It demonstrates a confidential web client without returning OIDC tokens to the browser.

## Requirements

- Node.js 24 and the root project dependencies installed.
- PostgreSQL and Redis running; the API migrations applied.
- Identity API running at `http://127.0.0.1:3005`.
- `OIDC_BFF_CLIENT_SECRET` set in the ignored root `.env` file to the same fresh value the API will load. Generate one locally with `openssl rand -base64 48` and restart the API afterward.
- A local account with an active status and verified primary email. The disabled email adapter does not deliver verification tokens.

Start the client:

```sh
npm run bff:dev
```

Then open `http://127.0.0.1:4300`. The client shows login, optional MFA, scope consent, a protected UserInfo view, and logout. The browser receives an opaque HttpOnly BFF cookie; OIDC access, ID, and refresh tokens stay in the BFF process.

This demo keeps sessions and pending flows in memory and binds to loopback. It is not a production session store. See [BFF integration guidance](../../docs/bff-integration.md) and the [API contract](../../docs/api-reference.md).
