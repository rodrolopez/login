import { randomUUID } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { IdentityRepository } from '../src/identity/identity.repository.js';
import { createPostgresPool } from '../src/infrastructure/postgres/pool.js';
import { runMigrations } from '../src/infrastructure/postgres/migrations.js';
import { createRedisClient } from '../src/infrastructure/redis/client.js';
import { IdentitySessionRevocationService } from '../src/sessions/session.service.js';
import { readTestInfrastructureConfig } from './helpers/testInfrastructure.js';
import type { GoogleOidcClient, GoogleIdentityClaims } from '../src/auth/google-oidc-client.js';
import { TestEmailProvider } from '../src/email/email-provider.js';

const testConfig = readTestInfrastructureConfig();
const password = `test password ${randomUUID()}`;

function stateFromLocation(location: string | undefined): string {
  if (!location) throw new Error('Google authorization redirect is missing');
  const state = new URL(location).searchParams.get('state');
  if (!state) throw new Error('Google authorization redirect is missing state');
  return state;
}

describe.skipIf(!testConfig)('authentication HTTP integration', () => {
  const pool = testConfig ? createPostgresPool(testConfig.postgres) : undefined;
  const redis = testConfig ? createRedisClient(testConfig.redis) : undefined;
  const repository = pool ? new IdentityRepository(pool) : undefined;
  const rateLimitKeySecret = randomUUID();
  const emailProvider = new TestEmailProvider();
  const app =
    pool && redis ? createApp({ pool, redis, rateLimitKeySecret, emailProvider }) : createApp();
  const secondApp =
    pool && redis ? createApp({ pool, redis, rateLimitKeySecret, emailProvider }) : createApp();

  beforeAll(async () => {
    if (!pool || !redis) throw new Error('Isolated HTTP test infrastructure is unavailable');
    await runMigrations(pool);
    await redis.connect();
  });

  afterAll(async () => {
    await Promise.allSettled([pool?.end(), redis?.quit()]);
  });

  it('registers a normalized account, creates a secure API session cookie, and logs out', async () => {
    const agent = request.agent(app);
    const email = `  New-${randomUUID()}@Example.Test  `;
    const registered = await agent
      .post('/auth/register')
      .set('Accept-Language', 'es-AR,es;q=0.9,en;q=0.8')
      .send({ email, password });

    expect(registered.status).toBe(201);
    expect(registered.body.userId).toMatch(/^[0-9a-f-]{36}$/i);
    expect(registered.headers['set-cookie']).toBeUndefined();
    expect(registered.body).not.toHaveProperty('accessToken');

    const verificationEmail = emailProvider.takeLast('email_verification');
    expect(verificationEmail?.recipient).toBe(email.trim().toLowerCase());
    const verified = await agent
      .post('/auth/email/verification/confirm')
      .send({ token: verificationEmail?.token });
    expect(verified.status).toBe(200);

    const loggedIn = await agent
      .post('/auth/login')
      .set('Accept-Language', 'en-US,en;q=0.9')
      .send({ email: email.trim().toLowerCase(), password });

    expect(loggedIn.status).toBe(200);
    expect(loggedIn.body).toEqual({ userId: registered.body.userId });
    expect(loggedIn.headers['set-cookie']).toHaveLength(1);
    expect(String(loggedIn.headers['set-cookie'])).toMatch(
      /^identity_session=[^;]+; Path=\/; HttpOnly; SameSite=Lax; Max-Age=28800$/,
    );
    expect(String(loggedIn.headers['set-cookie'])).not.toContain('Secure');
    expect(loggedIn.body).not.toHaveProperty('accessToken');
    expect((await agent.get('/auth/session')).body).toEqual({ userId: registered.body.userId });
    expect(await repository?.findPasswordCredential(registered.body.userId)).toMatchObject({
      userId: registered.body.userId,
    });

    const logout = await agent.post('/auth/logout');
    expect(logout.status).toBe(204);
    expect(String(logout.headers['set-cookie'])).toMatch(/identity_session=;.*Max-Age=0/);
    expect((await agent.get('/auth/session')).status).toBe(401);
  });

  it('returns the same generic login error for an incorrect password and an unknown email', async () => {
    const email = `known-${randomUUID()}@example.test`;
    const registered = await request(app).post('/auth/register').send({ email, password });
    expect(registered.status).toBe(201);

    const wrongPassword = await request(app)
      .post('/auth/login')
      .set('Accept-Language', 'es')
      .send({ email, password: 'wrong password 1234' });
    const unknownEmail = await request(app)
      .post('/auth/login')
      .set('Accept-Language', 'es')
      .send({ email: `unknown-${randomUUID()}@example.test`, password });

    expect(wrongPassword.status).toBe(401);
    expect(unknownEmail.status).toBe(401);
    expect(wrongPassword.body).toEqual({ error: 'Credenciales inválidas.' });
    expect(unknownEmail.body).toEqual(wrongPassword.body);
    expect(JSON.stringify(wrongPassword.body)).not.toMatch(/stack|password|email/i);
  });

  it('revokes API sessions when accounts are disabled, suspended, or anonymized', async () => {
    if (!pool || !redis) throw new Error('Session infrastructure is unavailable');
    const lifecycle = new IdentitySessionRevocationService(pool, redis);
    const transitions = [
      ['disabled', (userId: string) => lifecycle.disableAccount(userId)],
      ['suspended', (userId: string) => lifecycle.suspendAccount(userId)],
      ['anonymized', (userId: string) => lifecycle.anonymizeAccount(userId)],
    ] as const;

    for (const [status, transition] of transitions) {
      const agent = request.agent(app);
      const email = `${status}-${randomUUID()}@example.test`;
      const registered = await agent.post('/auth/register').send({ email, password });
      const verificationEmail = emailProvider.takeLast('email_verification');
      const verified = await agent
        .post('/auth/email/verification/confirm')
        .send({ token: verificationEmail?.token });
      const loggedIn = await agent.post('/auth/login').send({ email, password });
      expect(registered.status).toBe(201);
      expect(verified.status).toBe(200);
      expect(loggedIn.status).toBe(200);
      expect((await agent.get('/auth/session')).status).toBe(200);
      expect(await transition(registered.body.userId)).toBe(true);
      expect((await agent.get('/auth/session')).status).toBe(401);
      expect(await redis.scard(`identity:api-session:account:${registered.body.userId}`)).toBe(0);
      if (status === 'disabled') {
        const rejectedLogin = await request(app).post('/auth/login').send({ email, password });
        expect(rejectedLogin.status).toBe(401);
        expect(rejectedLogin.body).toEqual({ error: 'Credenciales inválidas.' });
      }
    }
  });

  it('limits repeated login attempts using the shared Redis counter', async () => {
    const email = `limited-${randomUUID()}@example.test`;
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const response = await request(app).post('/auth/login').send({
        email,
        password: 'wrong password 1234',
      });
      expect(response.status).toBe(401);
    }

    const limited = await request(app)
      .post('/auth/login')
      .set('Accept-Language', 'es')
      .send({ email, password: 'wrong password 1234' });
    const sharedLimit = await request(secondApp)
      .post('/auth/login')
      .set('Accept-Language', 'es')
      .send({ email, password: 'wrong password 1234' });
    expect(limited.status).toBe(429);
    expect(sharedLimit.status).toBe(429);
    expect(limited.headers['retry-after']).toMatch(/\d+/);
    expect(limited.body).toEqual({ error: 'Demasiados intentos. Volvé a intentarlo más tarde.' });
  });

  it('localizes malformed and invalid payload responses without returning parser details', async () => {
    const malformed = await request(app)
      .post('/auth/login')
      .set('Accept-Language', 'en')
      .set('Content-Type', 'application/json')
      .send('{"email":');
    const invalid = await request(app)
      .post('/auth/register')
      .set('Accept-Language', 'es')
      .send({ email: 'not-an-email', password: 'short', extra: 'not allowed' });

    expect(malformed.status).toBe(400);
    expect(malformed.headers['cache-control']).toBe('no-store');
    expect(malformed.body).toEqual({ error: 'The request contains invalid data.' });
    expect(JSON.stringify(malformed.body)).not.toMatch(/stack|syntaxerror|entity/i);
    expect(invalid.status).toBe(400);
    expect(invalid.body.error).toBe('La solicitud contiene datos inválidos.');
    expect(invalid.body.fields).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ field: 'email' }),
        expect.objectContaining({ field: 'password' }),
        expect.objectContaining({ field: 'body' }),
      ]),
    );
  });

  it('creates a new account for a mocked Google identity and issues the API session cookie', async () => {
    if (!pool || !redis) throw new Error('Isolated HTTP test infrastructure is unavailable');
    const claims: GoogleIdentityClaims = {
      subject: `google-${randomUUID()}`,
      email: `google-new-${randomUUID()}@example.test`,
      emailVerified: true,
    };
    let authorization: { state: string; nonce: string; codeVerifier: string } | undefined;
    const googleOidcClient: GoogleOidcClient = {
      authorizationUrl: async (input) => {
        authorization = input;
        return `https://accounts.google.com/o/oauth2/v2/auth?state=${input.state}`;
      },
      completeAuthorization: async (input) => {
        expect(input.expectedState).toBe(input.callbackUrl.searchParams.get('state'));
        expect(input.expectedNonce).toBe(authorization?.nonce);
        expect(input.codeVerifier).toBe(authorization?.codeVerifier);
        return claims;
      },
    };
    const googleApp = createApp({
      pool,
      redis,
      rateLimitKeySecret,
      googleOidcClient,
      googleRedirectUri: 'http://127.0.0.1:3005/auth/google/callback',
    });
    const agent = request.agent(googleApp);
    const start = await agent.get('/auth/google');
    expect(start.status).toBe(302);
    expect(start.headers.location).toContain('accounts.google.com');
    expect(String(start.headers['set-cookie'])).toMatch(
      /^identity_google_state=[^;]+; Path=\/auth\/google\/callback; HttpOnly; SameSite=Lax; Max-Age=300$/,
    );
    const state = stateFromLocation(start.headers.location);
    const callback = await agent.get(`/auth/google/callback?code=mock-code&state=${state}`);

    expect(callback.status).toBe(200);
    expect(callback.body.userId).toMatch(/^[0-9a-f-]{36}$/i);
    expect(callback.headers['set-cookie']).toHaveLength(2);
    expect(String(callback.headers['set-cookie'])).toMatch(
      /(?:^|,)identity_session=[^;,]+;.*HttpOnly/,
    );
    expect((await agent.get('/auth/session')).body).toEqual(callback.body);
    const account = await repository?.findAccountById(callback.body.userId);
    expect(account?.emails[0]).toMatchObject({ email: claims.email, verifiedAt: expect.any(Date) });
    const identity = await pool.query(
      `SELECT provider, issuer, subject FROM identity_api.external_identities WHERE user_id = $1`,
      [callback.body.userId],
    );
    expect(identity.rows).toEqual([
      { provider: 'google', issuer: 'https://accounts.google.com', subject: claims.subject },
    ]);
  });

  it('does not link Google to a local account based only on a matching email', async () => {
    if (!pool || !redis) throw new Error('Isolated HTTP test infrastructure is unavailable');
    const email = `local-google-${randomUUID()}@example.test`;
    const registered = await request(app).post('/auth/register').send({ email, password });
    expect(registered.status).toBe(201);
    let state = '';
    const googleOidcClient: GoogleOidcClient = {
      authorizationUrl: async (input) => {
        state = input.state;
        return `https://accounts.google.com/auth?state=${state}`;
      },
      completeAuthorization: async () => ({
        subject: `unlinked-${randomUUID()}`,
        email,
        emailVerified: true,
      }),
    };
    const googleApp = createApp({ pool, redis, rateLimitKeySecret, googleOidcClient });
    const agent = request.agent(googleApp);
    const start = await agent.get('/auth/google');
    state = stateFromLocation(start.headers.location);
    const callback = await agent.get(`/auth/google/callback?code=mock&state=${state}`);

    expect(callback.status).toBe(409);
    expect(callback.body.error).toMatch(/cuenta local|local account/i);
    expect(String(callback.headers['set-cookie'])).not.toContain('identity_session=');
    const linked = await pool.query(
      `SELECT count(*)::int AS count FROM identity_api.external_identities WHERE user_id = $1`,
      [registered.body.userId],
    );
    expect(linked.rows[0]?.count).toBe(0);
  });

  it('reuses an already-linked Google subject without creating a duplicate identity', async () => {
    if (!pool || !redis || !repository)
      throw new Error('Isolated HTTP test infrastructure is unavailable');
    const account = await repository.createAccount({
      email: `linked-${randomUUID()}@example.test`,
      emailVerified: true,
    });
    const subject = `google-linked-${randomUUID()}`;
    await repository.linkExternalIdentity({
      userId: account.id,
      provider: 'google',
      issuer: 'https://accounts.google.com',
      subject,
    });
    const googleOidcClient: GoogleOidcClient = {
      authorizationUrl: async ({ state }) => `https://accounts.google.com/auth?state=${state}`,
      completeAuthorization: async () => ({
        subject,
        email: `different-email-${randomUUID()}@example.test`,
        emailVerified: true,
      }),
    };
    const googleApp = createApp({ pool, redis, rateLimitKeySecret, googleOidcClient });
    const agent = request.agent(googleApp);
    const start = await agent.get('/auth/google');
    const state = stateFromLocation(start.headers.location);
    const callback = await agent.get(`/auth/google/callback?code=mock&state=${state}`);

    expect(callback.status).toBe(200);
    expect(callback.body).toEqual({ userId: account.id });
    const identities = await pool.query(
      `SELECT count(*)::int AS count FROM identity_api.external_identities
       WHERE issuer = $1 AND subject = $2`,
      ['https://accounts.google.com', subject],
    );
    expect(identities.rows[0]?.count).toBe(1);
  });

  it('rejects invalid state and hides errors from the mocked Google provider', async () => {
    if (!pool || !redis) throw new Error('Isolated HTTP test infrastructure is unavailable');
    const googleOidcClient: GoogleOidcClient = {
      authorizationUrl: async ({ state }) => `https://accounts.google.com/auth?state=${state}`,
      completeAuthorization: async () => {
        throw new Error('sensitive provider response details');
      },
    };
    const googleApp = createApp({ pool, redis, rateLimitKeySecret, googleOidcClient });
    const agent = request.agent(googleApp);
    const start = await agent.get('/auth/google');
    expect(stateFromLocation(start.headers.location)).toBeTruthy();
    const invalidState = await agent.get('/auth/google/callback?code=mock&state=wrong');
    expect(invalidState.status).toBe(400);
    const retryAgent = request.agent(googleApp);
    const retryStart = await retryAgent.get('/auth/google');
    const retryState = stateFromLocation(retryStart.headers.location);
    const providerFailure = await retryAgent.get(
      `/auth/google/callback?code=mock&state=${retryState}`,
    );
    expect(providerFailure.status).toBe(502);
    expect(providerFailure.body.error).toMatch(/Google|Google/i);
    expect(JSON.stringify(providerFailure.body)).not.toContain('sensitive provider response');
  });
});
