import { createHash, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import request from 'supertest';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { createApp } from '../src/app.js';
import { IdentityRepository } from '../src/identity/identity.repository.js';
import { createPostgresPool } from '../src/infrastructure/postgres/pool.js';
import { runMigrations } from '../src/infrastructure/postgres/migrations.js';
import { createRedisClient } from '../src/infrastructure/redis/client.js';
import {
  ApiSessionService,
  IdentitySessionRevocationService,
} from '../src/sessions/session.service.js';
import {
  BFF_REFERENCE_CLIENT_ID,
  CONFIDENTIAL_TEST_CLIENT_ID,
  createOidcProvider,
  OIDC_MOUNT_PATH,
  PUBLIC_TEST_CLIENT_ID,
} from '../src/oidc/provider.js';
import { createBffRuntime } from '../examples/bff-client/server.js';
import { readTestInfrastructureConfig } from './helpers/testInfrastructure.js';
import { TestEmailProvider } from '../src/email/email-provider.js';

const testConfig = readTestInfrastructureConfig();
const issuerHost = '127.0.0.1:3005';

describe.skipIf(!testConfig)('OpenID Connect interoperability', () => {
  const pool = testConfig ? createPostgresPool(testConfig.postgres) : undefined;
  const redis = testConfig ? createRedisClient(testConfig.redis) : undefined;
  const oidc =
    pool && redis
      ? createOidcProvider({ pool, redis, issuer: 'http://127.0.0.1:3005/oidc' })
      : undefined;
  const emailProvider = new TestEmailProvider();
  const app =
    pool && redis && oidc
      ? createApp({
          pool,
          redis,
          rateLimitKeySecret: randomUUID(),
          oidcProvider: oidc.provider,
          emailProvider,
        })
      : createApp();
  const repository = pool ? new IdentityRepository(pool) : undefined;

  beforeAll(async () => {
    if (!pool || !redis) throw new Error('Isolated test infrastructure is unavailable');
    await runMigrations(pool);
    await redis.connect();
  });

  afterAll(async () => {
    await Promise.allSettled([pool?.end(), redis?.quit()]);
  });

  afterEach(() => vi.unstubAllEnvs());

  it('publishes issuer metadata and public JWKS without private signing material', async () => {
    if (!oidc) throw new Error('OIDC provider is unavailable');
    const metadata = await request(app)
      .get(`${OIDC_MOUNT_PATH}/.well-known/openid-configuration`)
      .set('Host', issuerHost);
    expect(metadata.status).toBe(200);
    expect(metadata.body.issuer).toBe(oidc.issuer);
    expect(metadata.body.authorization_endpoint).toBe(`${oidc.issuer}/auth`);
    expect(metadata.body.code_challenge_methods_supported).toContain('S256');
    expect(metadata.body.grant_types_supported).toEqual(['authorization_code', 'refresh_token']);
    expect(metadata.body.response_types_supported).toEqual(['code']);
    expect(metadata.body.end_session_endpoint).toBe(`${oidc.issuer}/session/end`);
    expect(metadata.body).not.toHaveProperty('pushed_authorization_request_endpoint');
    const localhostMetadata = await request(app)
      .get(`${OIDC_MOUNT_PATH}/.well-known/openid-configuration`)
      .set('Host', 'localhost:3005');
    expect(localhostMetadata.status).toBe(200);
    expect(localhostMetadata.body.issuer).toBe(oidc.issuer);
    const unexpectedHost = await request(app)
      .get(`${OIDC_MOUNT_PATH}/.well-known/openid-configuration`)
      .set('Host', 'attacker.example');
    expect(unexpectedHost.status).toBe(400);

    const jwks = await request(app)
      .get(new URL(metadata.body.jwks_uri).pathname)
      .set('Host', issuerHost);
    expect(jwks.status).toBe(200);
    expect(jwks.body.keys).toHaveLength(1);
    expect(jwks.body.keys[0]).toMatchObject({ kty: 'RSA', use: 'sig', alg: 'RS256' });
    expect(jwks.body.keys[0]).not.toHaveProperty('d');
    expect(jwks.body.keys[0]).not.toHaveProperty('p');
  });

  it('completes verified-account Authorization Code with mandatory PKCE', async () => {
    if (!oidc || !pool || !redis) throw new Error('OIDC provider is unavailable');
    const agent = request.agent(app);
    const email = `oidc-${randomUUID()}@example.test`;
    const password = `Pass ${randomUUID()}!`;
    const registered = await agent.post('/auth/register').send({ email, password });
    expect(registered.status).toBe(201);
    const account = await repository?.findAccountById(registered.body.userId);
    expect(account?.status).toBe('pending');
    const verificationEmail = emailProvider.takeLast('email_verification');
    const verified = await agent
      .post('/auth/email/verification/confirm')
      .send({ token: verificationEmail?.token });
    expect(verified.status).toBe(200);
    expect((await repository?.findAccountById(registered.body.userId))?.status).toBe('active');

    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const state = randomUUID();
    const nonce = randomUUID();
    const authorization = await agent.get(`${OIDC_MOUNT_PATH}/auth`).set('Host', issuerHost).query({
      client_id: PUBLIC_TEST_CLIENT_ID,
      redirect_uri: 'http://127.0.0.1:4100/callback',
      response_type: 'code',
      scope: 'openid email offline_access',
      prompt: 'consent',
      state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    expect([302, 303]).toContain(authorization.status);
    const oidcCookies = authorization.headers['set-cookie'] as string[] | undefined;
    expect(oidcCookies?.length).toBeGreaterThan(0);
    for (const cookie of oidcCookies ?? []) {
      expect(cookie.toLowerCase()).toContain('httponly');
      expect(cookie.toLowerCase()).toContain('samesite=lax');
      expect(cookie.toLowerCase()).not.toContain('secure');
    }
    const authorizationLocation = authorization.headers.location;
    if (!authorizationLocation) throw new Error('Missing OIDC login interaction redirect');
    const interactionPath = new URL(authorizationLocation, oidc.issuer).pathname;
    const interaction = await agent.get(interactionPath).set('Host', issuerHost);
    expect(interaction.status).toBe(200);
    expect(interaction.body.prompt).toBe('login');

    const login = await agent
      .post('/auth/login')
      .set('Host', issuerHost)
      .send({ email, password, interactionUid: interaction.body.interactionUid });
    expect([302, 303]).toContain(login.status);
    const loginLocation = login.headers.location;
    if (!loginLocation) throw new Error('Missing OIDC consent interaction redirect');
    const resume = await agent
      .get(new URL(loginLocation, oidc.issuer).pathname)
      .set('Host', issuerHost);
    expect([302, 303]).toContain(resume.status);
    const consentLocation = resume.headers.location;
    if (!consentLocation) throw new Error('Missing OIDC consent interaction redirect');
    const consent = await agent
      .get(new URL(consentLocation, oidc.issuer).pathname)
      .set('Host', issuerHost);
    expect(consent.status).toBe(200);
    expect(consent.body.prompt).toBe('consent');
    const consentResult = await agent
      .post(`${OIDC_MOUNT_PATH}/interaction/${consent.body.interactionUid}/consent`)
      .set('Host', issuerHost)
      .send({ approve: true });
    expect([302, 303]).toContain(consentResult.status);
    const consentResumeLocation = consentResult.headers.location;
    if (!consentResumeLocation) throw new Error('Missing OIDC authorization resume redirect');
    const callbackRedirect = await agent
      .get(new URL(consentResumeLocation, oidc.issuer).pathname)
      .set('Host', issuerHost);
    expect([302, 303]).toContain(callbackRedirect.status);
    const callbackLocation = callbackRedirect.headers.location;
    if (!callbackLocation) throw new Error('Missing client callback redirect');
    const callback = new URL(callbackLocation);
    expect(callback.origin + callback.pathname).toBe('http://127.0.0.1:4100/callback');
    expect(callback.searchParams.get('state')).toBe(state);
    const code = callback.searchParams.get('code');
    expect(code).toBeTruthy();

    const tokenResponse = await request(app)
      .post(`${OIDC_MOUNT_PATH}/token`)
      .set('Host', issuerHost)
      .type('form')
      .send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'http://127.0.0.1:4100/callback',
        client_id: PUBLIC_TEST_CLIENT_ID,
        code_verifier: verifier,
      });
    expect(tokenResponse.status).toBe(200);
    expect(tokenResponse.body).toHaveProperty('access_token');
    expect(tokenResponse.body).toHaveProperty('id_token');
    expect(tokenResponse.body.token_type).toBe('Bearer');
    expect(tokenResponse.body).toHaveProperty('refresh_token');
    const savedGrant = await pool.query<{ account_id: string }>(
      'SELECT account_id FROM identity_api.oidc_grants WHERE account_id = $1',
      [registered.body.userId],
    );
    expect(savedGrant.rows.length).toBeGreaterThan(0);

    const rotated = await request(app)
      .post(`${OIDC_MOUNT_PATH}/token`)
      .set('Host', issuerHost)
      .type('form')
      .send({
        grant_type: 'refresh_token',
        refresh_token: tokenResponse.body.refresh_token,
        client_id: PUBLIC_TEST_CLIENT_ID,
      });
    expect(rotated.status).toBe(200);
    expect(rotated.body.refresh_token).toBeTruthy();
    expect(rotated.body.refresh_token).not.toBe(tokenResponse.body.refresh_token);

    const sessionIndex = `identity:oidc:Session:index:accountId:${Buffer.from(registered.body.userId).toString('base64url')}`;
    const sessionKeys = await redis.smembers(sessionIndex);
    expect(sessionKeys.length).toBeGreaterThan(0);
    const storedSessions = await Promise.all(
      sessionKeys.map(
        async (key) =>
          JSON.parse((await redis.get(key)) ?? '{}') as {
            authorizations?: Record<string, { grantId?: string }>;
          },
      ),
    );
    expect(
      storedSessions.some((session) =>
        Object.values(session.authorizations ?? {}).some((authorization) => authorization.grantId),
      ),
    ).toBe(true);

    const logoutPage = await agent
      .get(`${OIDC_MOUNT_PATH}/session/end`)
      .set('Host', issuerHost)
      .query({ id_token_hint: tokenResponse.body.id_token });
    expect(logoutPage.status).toBe(200);
    expect(logoutPage.text).toContain('Confirm sign out');
    const xsrf = logoutPage.text.match(/name="xsrf" value="([^"]+)"/)?.[1];
    expect(xsrf).toBeTruthy();
    const logout = await agent
      .post(`${OIDC_MOUNT_PATH}/session/end/confirm`)
      .set('Host', issuerHost)
      .type('form')
      .send({ xsrf, logout: 'yes' });
    expect(logout.status).toBe(303);
    expect(String(logout.headers['set-cookie'])).toMatch(/session=;/);
    const postLogoutRefresh = await request(app)
      .post(`${OIDC_MOUNT_PATH}/token`)
      .set('Host', issuerHost)
      .type('form')
      .send({
        grant_type: 'refresh_token',
        refresh_token: rotated.body.refresh_token,
        client_id: PUBLIC_TEST_CLIENT_ID,
      });
    expect(postLogoutRefresh.status).toBe(400);
    expect(postLogoutRefresh.body.error).toBe('invalid_grant');
  });

  it('rejects missing PKCE, unregistered clients, and unregistered redirect URIs', async () => {
    const base = {
      redirect_uri: 'http://127.0.0.1:4100/callback',
      response_type: 'code',
      scope: 'openid email',
      state: randomUUID(),
    };
    const missingPkce = await request(app)
      .get(`${OIDC_MOUNT_PATH}/auth`)
      .set('Host', issuerHost)
      .query({
        ...base,
        client_id: PUBLIC_TEST_CLIENT_ID,
      });
    expect([302, 303]).toContain(missingPkce.status);
    const missingPkceLocation = missingPkce.headers.location;
    if (!missingPkceLocation) throw new Error('Missing PKCE rejection response');
    expect(new URL(missingPkceLocation).searchParams.get('error')).toBe('invalid_request');

    const unknownClient = await request(app)
      .get(`${OIDC_MOUNT_PATH}/auth`)
      .set('Host', issuerHost)
      .query({
        ...base,
        client_id: `unregistered-${randomUUID()}`,
        code_challenge: randomBytes(32).toString('base64url'),
        code_challenge_method: 'S256',
      });
    expect(unknownClient.status).toBe(400);

    const invalidRedirect = await request(app)
      .get(`${OIDC_MOUNT_PATH}/auth`)
      .set('Host', issuerHost)
      .query({
        ...base,
        client_id: PUBLIC_TEST_CLIENT_ID,
        redirect_uri: 'http://attacker.example/callback',
        code_challenge: randomBytes(32).toString('base64url'),
        code_challenge_method: 'S256',
      });
    expect(invalidRedirect.status).toBe(400);
    expect(invalidRedirect.headers.location).toBeUndefined();
  });

  it('registers the confidential static client with client secret authentication', async () => {
    if (!oidc) throw new Error('OIDC provider is unavailable');
    const metadata = await request(app)
      .get(`${OIDC_MOUNT_PATH}/.well-known/openid-configuration`)
      .set('Host', issuerHost);
    expect(metadata.status).toBe(200);
    const publicClient = await oidc.provider.Client.find(PUBLIC_TEST_CLIENT_ID);
    const confidentialClient = await oidc.provider.Client.find(CONFIDENTIAL_TEST_CLIENT_ID);
    expect(publicClient?.clientAuthMethod).toBe('none');
    expect(publicClient?.redirectUris).toContain('http://127.0.0.1:4100/callback');
    expect(confidentialClient?.clientAuthMethod).toBe('client_secret_basic');
    expect(confidentialClient?.redirectUris).toContain('http://127.0.0.1:4200/callback');
    expect(oidc.confidentialClientSecret.length).toBeGreaterThanOrEqual(32);
  });

  it('runs the reference BFF through PKCE, server-side tokens, protected userinfo, and logout', async () => {
    if (!oidc || !pool || !redis) throw new Error('OIDC provider is unavailable');
    const registeredClient = await oidc.provider.Client.find(BFF_REFERENCE_CLIENT_ID);
    expect(registeredClient?.clientAuthMethod).toBe('client_secret_basic');
    expect(registeredClient?.redirectUris).toContain('http://127.0.0.1:4300/callback');
    expect(registeredClient?.postLogoutRedirectUris).toContain(
      'http://127.0.0.1:4300/logout/callback',
    );

    const email = `bff-${randomUUID()}@example.test`;
    const password = `Bff test ${randomUUID()}!`;
    const registration = await request(app).post('/auth/register').send({ email, password });
    expect(registration.status).toBe(201);
    const verificationEmail = emailProvider.takeLast('email_verification');
    expect(verificationEmail?.token).toBeDefined();
    expect(
      (
        await request(app)
          .post('/auth/email/verification/confirm')
          .send({ token: verificationEmail?.token })
      ).status,
    ).toBe(200);

    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input, init) => {
      const rawUrl = input instanceof Request ? input.url : input.toString();
      const url = new URL(rawUrl);
      if (url.origin !== oidc.issuer.slice(0, oidc.issuer.lastIndexOf('/oidc'))) {
        return originalFetch(input, init);
      }
      const method = (
        init?.method ?? (input instanceof Request ? input.method : 'GET')
      ).toUpperCase();
      let apiRequest = request(app)
        [method.toLowerCase() as 'get' | 'post'](`${url.pathname}${url.search}`)
        .set('Host', issuerHost);
      const headers = new Headers(input instanceof Request ? input.headers : undefined);
      new Headers(init?.headers).forEach((value, key) => headers.set(key, value));
      headers.forEach((value, key) => {
        if (key.toLowerCase() !== 'host' && key.toLowerCase() !== 'content-length') {
          apiRequest = apiRequest.set(key, value);
        }
      });
      if (init?.body != null) {
        const body =
          typeof init.body === 'string'
            ? init.body
            : init.body instanceof URLSearchParams
              ? init.body.toString()
              : Buffer.from(init.body as ArrayBuffer);
        apiRequest = apiRequest.send(body);
      }
      const apiResponse = await apiRequest;
      const responseHeaders = new Headers();
      for (const [name, value] of Object.entries(apiResponse.headers)) {
        if (name.toLowerCase() === 'set-cookie' || name.toLowerCase() === 'content-length') {
          continue;
        }
        if (typeof value === 'string') responseHeaders.set(name, value);
      }
      const setCookies = apiResponse.headers['set-cookie'];
      for (const cookie of Array.isArray(setCookies)
        ? setCookies
        : setCookies
          ? [setCookies]
          : []) {
        responseHeaders.append('set-cookie', cookie);
      }
      const body =
        apiResponse.status === 204 || apiResponse.status === 304 ? null : apiResponse.text;
      return new Response(body, { status: apiResponse.status, headers: responseHeaders });
    };

    try {
      const bff = await createBffRuntime({
        issuer: oidc.issuer,
        identityBaseUrl: oidc.issuer.slice(0, oidc.issuer.lastIndexOf('/oidc')),
        baseUrl: 'http://127.0.0.1:4300',
        clientSecret: oidc.bffReferenceClientSecret,
        fetchImplementation: globalThis.fetch,
      });
      try {
        const browser = request.agent(bff.app);
        const start = await browser.get('/login');
        expect(start.status).toBe(200);
        const state = start.text.match(/name="state" value="([^"]+)"/)?.[1];
        expect(state).toBeTruthy();
        expect(start.headers['set-cookie']).toBeDefined();

        const login = await browser.post('/login').type('form').send({ state, email, password });
        expect(login.status).toBe(200);
        expect(login.text).toContain('Authorize reference BFF');
        const uid = login.text.match(/name="uid" value="([^"]+)"/)?.[1];
        expect(uid).toBeTruthy();

        const consent = await browser.post('/consent').type('form').send({ state, uid });
        expect(consent.status).toBe(303);
        expect(consent.headers.location).toBe('/protected');
        const bffSessionCookie = (consent.headers['set-cookie'] as string[] | undefined)?.find(
          (cookie) => cookie.startsWith('bff_session='),
        );
        expect(bffSessionCookie).toBeDefined();
        expect(String(consent.headers['set-cookie'])).not.toContain('access_token');

        const protectedResource = await browser
          .get('/protected')
          .set('Cookie', bffSessionCookie?.split(';', 1)[0] ?? '');
        expect(protectedResource.status).toBe(200);
        expect(protectedResource.body).toMatchObject({
          sub: registration.body.userId,
          email,
          email_verified: true,
        });
        expect(protectedResource.body).not.toHaveProperty('access_token');
        expect(protectedResource.body).not.toHaveProperty('refresh_token');
        expect(protectedResource.body).not.toHaveProperty('id_token');

        const home = await browser.get('/');
        const csrf = home.text.match(/name="csrf" value="([^"]+)"/)?.[1];
        expect(csrf).toBeTruthy();
        const logout = await browser.post('/logout').type('form').send({ csrf });
        expect(logout.status).toBe(303);
        const logoutLocation = logout.headers.location;
        if (!logoutLocation) throw new Error('Missing BFF logout redirect');
        const logoutUrl = new URL(logoutLocation);
        expect(logoutUrl.origin).toBe(oidc.issuer.slice(0, oidc.issuer.lastIndexOf('/oidc')));
        const stateAfterLogout = logoutUrl.searchParams.get('state');
        expect(stateAfterLogout).toBeTruthy();
        expect(
          (await browser.get('/logout/callback').query({ state: stateAfterLogout })).status,
        ).toBe(200);
        expect((await browser.get('/protected')).status).toBe(401);
      } finally {
        bff.close();
      }
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('marks OIDC session cookies Secure in production', async () => {
    if (!pool || !redis) throw new Error('OIDC infrastructure is unavailable');
    vi.stubEnv(
      'OIDC_CLIENTS',
      JSON.stringify([
        {
          client_id: 'production-cookie-test-client',
          redirect_uris: ['https://rp.example.test/callback'],
          response_types: ['code'],
          grant_types: ['authorization_code'],
          token_endpoint_auth_method: 'none',
          scope: 'openid',
        },
      ]),
    );
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwks = {
      keys: [
        {
          ...privateKey.export({ format: 'jwk' }),
          kid: randomUUID(),
          use: 'sig',
          alg: 'RS256',
        },
      ],
    };
    const productionOidc = createOidcProvider({
      pool,
      redis,
      issuer: 'https://identity-production.example.test/oidc',
      confidentialClientSecret: randomBytes(32).toString('base64url'),
      cookieKeys: [randomBytes(32).toString('base64url')],
      jwks,
      runtimeEnvironment: 'production',
    });
    let providerError: string | undefined;
    productionOidc.provider.on('server_error', (_context, error) => {
      providerError = error.message;
    });
    const productionApp = createApp({
      pool,
      redis,
      rateLimitKeySecret: randomUUID(),
      oidcProvider: productionOidc.provider,
    });
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const response = await request(productionApp)
      .get(`${OIDC_MOUNT_PATH}/auth`)
      .set('Host', 'identity-production.example.test')
      .set('X-Forwarded-Proto', 'https')
      .query({
        client_id: 'production-cookie-test-client',
        redirect_uri: 'https://rp.example.test/callback',
        response_type: 'code',
        scope: 'openid',
        state: randomUUID(),
        code_challenge: challenge,
        code_challenge_method: 'S256',
      });
    expect([302, 303], providerError).toContain(response.status);
    const setCookies = String(response.headers['set-cookie']).toLowerCase();
    expect(setCookies).toContain('httponly');
    expect(setCookies).toContain('samesite=lax');
    expect(setCookies).toContain('secure');
  });

  it('revokes API sessions, refresh tokens, and grants when an account is disabled', async () => {
    if (!oidc || !pool || !redis) throw new Error('OIDC provider is unavailable');
    const email = `revoked-${randomUUID()}@example.test`;
    const password = `Pass ${randomUUID()}!`;
    const registered = await request(app).post('/auth/register').send({ email, password });
    expect(registered.status).toBe(201);
    const verificationEmail = emailProvider.takeLast('email_verification');
    const verified = await request(app)
      .post('/auth/email/verification/confirm')
      .send({ token: verificationEmail?.token });
    expect(verified.status).toBe(200);

    const client = await oidc.provider.Client.find(PUBLIC_TEST_CLIENT_ID);
    if (!client) throw new Error('Static OIDC test client was not initialized');
    const grant = new oidc.provider.Grant({
      accountId: registered.body.userId,
      clientId: client.clientId,
    });
    grant.addOIDCScope(['openid', 'email', 'offline_access']);
    const grantId = await grant.save();
    const refreshToken = new oidc.provider.RefreshToken({
      accountId: registered.body.userId,
      client,
      grantId,
      gty: 'authorization_code',
      scope: 'openid email offline_access',
    });
    const refreshTokenValue = await refreshToken.save();
    const accessToken = new oidc.provider.AccessToken({
      accountId: registered.body.userId,
      client,
      grantId,
      gty: 'authorization_code',
      scope: 'openid email',
    });
    const accessTokenValue = await accessToken.save();
    const apiSessions = new ApiSessionService(pool, redis);
    const apiSessionToken = await apiSessions.create(registered.body.userId);
    const lifecycle = new IdentitySessionRevocationService(pool, redis);

    expect(await lifecycle.disableAccount(registered.body.userId)).toBe(true);
    expect(await oidc.provider.RefreshToken.find(refreshTokenValue)).toBeUndefined();
    expect(await oidc.provider.AccessToken.find(accessTokenValue)).toBeUndefined();
    expect(
      (await pool.query('SELECT 1 FROM identity_api.oidc_grants WHERE grant_id = $1', [grantId]))
        .rowCount,
    ).toBe(0);
    const apiSession = await request(app)
      .get('/auth/session')
      .set('Cookie', `identity_session=${apiSessionToken}`);
    expect(apiSession.status).toBe(401);

    const refreshResponse = await request(app)
      .post(`${OIDC_MOUNT_PATH}/token`)
      .set('Host', issuerHost)
      .type('form')
      .send({
        grant_type: 'refresh_token',
        refresh_token: refreshTokenValue,
        client_id: PUBLIC_TEST_CLIENT_ID,
      });
    expect(refreshResponse.status).toBe(400);
    expect(refreshResponse.body.error).toBe('invalid_grant');
    const userInfoResponse = await request(app)
      .get(`${OIDC_MOUNT_PATH}/me`)
      .set('Host', issuerHost)
      .set('Authorization', `Bearer ${accessTokenValue}`);
    expect(userInfoResponse.status).toBe(401);
  });
});
