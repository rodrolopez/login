import { createHash, randomBytes, randomUUID } from 'node:crypto';
import request from 'supertest';
import { generate, verify } from 'otplib';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { createPostgresPool } from '../src/infrastructure/postgres/pool.js';
import { runMigrations } from '../src/infrastructure/postgres/migrations.js';
import { createRedisClient } from '../src/infrastructure/redis/client.js';
import {
  createOidcProvider,
  OIDC_MOUNT_PATH,
  PUBLIC_TEST_CLIENT_ID,
} from '../src/oidc/provider.js';
import { readTestInfrastructureConfig } from './helpers/testInfrastructure.js';
import { TestEmailProvider } from '../src/email/email-provider.js';
import type { GoogleIdentityClaims, GoogleOidcClient } from '../src/auth/google-oidc-client.js';

const testConfig = readTestInfrastructureConfig();
const issuerHost = '127.0.0.1:3005';

describe.skipIf(!testConfig)('TOTP MFA integration', () => {
  const pool = testConfig ? createPostgresPool(testConfig.postgres) : undefined;
  const redis = testConfig ? createRedisClient(testConfig.redis) : undefined;
  const oidc =
    pool && redis
      ? createOidcProvider({ pool, redis, issuer: 'http://127.0.0.1:3005/oidc' })
      : undefined;
  const emailProvider = new TestEmailProvider();
  const mfaEncryptionKey = randomBytes(32).toString('hex');
  const app =
    pool && redis
      ? createApp({
          pool,
          redis,
          rateLimitKeySecret: randomUUID(),
          mfaEncryptionKey,
          ...(oidc ? { oidcProvider: oidc.provider } : {}),
          emailProvider,
        })
      : createApp();

  beforeAll(async () => {
    if (!pool || !redis) throw new Error('Isolated test infrastructure is unavailable');
    await runMigrations(pool);
    await redis.connect();
  });

  afterAll(async () => {
    await Promise.allSettled([pool?.end(), redis?.quit()]);
  });

  async function createSignedInAccount() {
    const agent = request.agent(app);
    const email = `mfa-${randomUUID()}@example.test`;
    const password = `Mfa test ${randomUUID()}!`;
    const registration = await agent.post('/auth/register').send({ email, password });
    expect(registration.status).toBe(201);
    const emailAction = emailProvider.takeLast('email_verification');
    expect(emailAction?.token).toBeDefined();
    expect(
      (await agent.post('/auth/email/verification/confirm').send({ token: emailAction?.token }))
        .status,
    ).toBe(200);
    const login = await agent.post('/auth/login').send({ email, password });
    expect(login.status).toBe(200);
    return { agent, email, password, userId: registration.body.userId as string };
  }

  async function enrollTotp(agent: ReturnType<typeof request.agent>, userId: string) {
    const started = await agent.post('/auth/mfa/totp/enrollment');
    expect(started.status).toBe(200);
    expect(started.body.otpauthUri).toMatch(/^otpauth:\/\/totp\//);
    expect(started.body.secret).toBeTruthy();
    const token = await generate({ secret: started.body.secret });
    const confirmed = await agent.post('/auth/mfa/totp/confirm').send({ token });
    expect(confirmed.status).toBe(200);
    expect(confirmed.body.recoveryCodes).toHaveLength(10);
    const stored = await pool?.query<{
      secret_ciphertext: Buffer;
      last_totp_counter: string;
    }>(
      `SELECT secret_ciphertext, last_totp_counter FROM identity_api.user_totp_credentials
       WHERE user_id = $1`,
      [userId],
    );
    expect(stored?.rows[0]?.secret_ciphertext.toString('utf8')).not.toContain(started.body.secret);
    return {
      secret: started.body.secret as string,
      recoveryCodes: confirmed.body.recoveryCodes as string[],
      counter: BigInt(stored?.rows[0]?.last_totp_counter ?? '-1'),
    };
  }

  async function loginChallenge(
    agent: ReturnType<typeof request.agent>,
    email: string,
    password: string,
  ) {
    const result = await agent.post('/auth/login').send({ email, password });
    expect(result.status).toBe(202);
    expect(result.body.mfaRequired).toBe(true);
    expect(result.body.challengeId).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(result.headers['set-cookie']).toBeUndefined();
    return result.body.challengeId as string;
  }

  async function nextAcceptedTotp(secret: string, previousCounter: bigint): Promise<string> {
    const targetCounter = previousCounter + 1n;
    return generate({ secret, epoch: Number(targetCounter) * 30 });
  }

  async function invalidTotp(secret: string): Promise<string> {
    for (let value = 0; value < 1_000_000; value += 1) {
      const token = String(value).padStart(6, '0');
      if (!(await verify({ secret, token })).valid) return token;
    }
    throw new Error('Could not produce an invalid TOTP fixture');
  }

  it('requires a valid API session to enroll TOTP', async () => {
    const response = await request(app).post('/auth/mfa/totp/enrollment');
    expect(response.status).toBe(401);
    expect(response.body).not.toHaveProperty('secret');
  });

  it('enrolls TOTP and requires a valid code before issuing an API session', async () => {
    const account = await createSignedInAccount();
    const enrollment = await enrollTotp(account.agent, account.userId);
    const loginAgent = request.agent(app);
    const challengeId = await loginChallenge(loginAgent, account.email, account.password);
    const invalid = await invalidTotp(enrollment.secret);

    const rejected = await loginAgent
      .post('/auth/mfa/totp/verify')
      .send({ challengeId, token: invalid });
    expect(rejected.status).toBe(401);
    expect(rejected.headers['set-cookie']).toBeUndefined();
    expect((await loginAgent.get('/auth/session')).status).toBe(401);

    const token = await nextAcceptedTotp(enrollment.secret, enrollment.counter);
    const accepted = await loginAgent.post('/auth/mfa/totp/verify').send({ challengeId, token });
    expect(accepted.status).toBe(200);
    expect(accepted.body.userId).toBe(account.userId);
    expect(String(accepted.headers['set-cookie'])).toContain('identity_session=');
    expect((await loginAgent.get('/auth/session')).body.userId).toBe(account.userId);
    expect(
      (await loginAgent.post('/auth/mfa/totp/verify').send({ challengeId, token })).status,
    ).toBe(401);
    const replayChallenge = await loginChallenge(loginAgent, account.email, account.password);
    expect(
      (await loginAgent.post('/auth/mfa/totp/verify').send({ challengeId: replayChallenge, token }))
        .status,
    ).toBe(401);
  });

  it('consumes a recovery code once and rejects reuse', async () => {
    const account = await createSignedInAccount();
    const enrollment = await enrollTotp(account.agent, account.userId);
    const recoveryCode = enrollment.recoveryCodes[0];
    expect(recoveryCode).toBeDefined();

    const challengeId = await loginChallenge(account.agent, account.email, account.password);
    const accepted = await account.agent
      .post('/auth/mfa/totp/verify')
      .send({ challengeId, recoveryCode });
    expect(accepted.status).toBe(200);
    expect(String(accepted.headers['set-cookie'])).toContain('identity_session=');

    const nextChallenge = await loginChallenge(account.agent, account.email, account.password);
    const reused = await account.agent
      .post('/auth/mfa/totp/verify')
      .send({ challengeId: nextChallenge, recoveryCode });
    expect(reused.status).toBe(401);
    expect(reused.headers['set-cookie']).toBeUndefined();
    const storedCode = await pool?.query<{ code_hash: string }>(
      `SELECT code_hash FROM identity_api.user_mfa_recovery_codes
       WHERE user_id = $1 ORDER BY created_at LIMIT 1`,
      [account.userId],
    );
    expect(storedCode?.rows[0]?.code_hash).not.toBe(recoveryCode);
    expect(storedCode?.rows[0]?.code_hash).toMatch(/^\$argon2id\$/);
  });

  it('blocks repeated invalid TOTP attempts through the shared Redis limiter', async () => {
    const account = await createSignedInAccount();
    const enrollment = await enrollTotp(account.agent, account.userId);
    const challengeId = await loginChallenge(account.agent, account.email, account.password);
    const invalid = await invalidTotp(enrollment.secret);
    const responses = [];
    for (let index = 0; index < 6; index += 1) {
      responses.push(
        await account.agent.post('/auth/mfa/totp/verify').send({ challengeId, token: invalid }),
      );
    }
    expect(responses.slice(0, 5).every((response) => response.status === 401)).toBe(true);
    expect(responses[5]?.status).toBe(429);
  });

  it('keeps an OIDC interaction at the login prompt until MFA succeeds', async () => {
    if (!oidc) throw new Error('OIDC provider is unavailable');
    const account = await createSignedInAccount();
    const enrollment = await enrollTotp(account.agent, account.userId);
    const verifier = randomBytes(32).toString('base64url');
    const pkceChallenge = createHash('sha256').update(verifier).digest('base64url');
    const authorization = await account.agent
      .get(`${OIDC_MOUNT_PATH}/auth`)
      .set('Host', issuerHost)
      .query({
        client_id: PUBLIC_TEST_CLIENT_ID,
        redirect_uri: 'http://127.0.0.1:4100/callback',
        response_type: 'code',
        scope: 'openid email',
        state: randomUUID(),
        nonce: randomUUID(),
        code_challenge: pkceChallenge,
        code_challenge_method: 'S256',
      });
    expect([302, 303]).toContain(authorization.status);
    const authorizationLocation = authorization.headers.location as string;
    const interactionPath = new URL(authorizationLocation, oidc.issuer).pathname;
    const interaction = await account.agent.get(interactionPath).set('Host', issuerHost);
    expect(interaction.body.prompt).toBe('login');

    const login = await account.agent.post('/auth/login').set('Host', issuerHost).send({
      email: account.email,
      password: account.password,
      interactionUid: interaction.body.interactionUid,
    });
    expect(login.status).toBe(202);
    expect(login.headers.location).toBeUndefined();
    expect(login.headers['set-cookie']).toBeUndefined();
    expect((await account.agent.get(interactionPath).set('Host', issuerHost)).body.prompt).toBe(
      'login',
    );

    const stored = await pool?.query<{ last_totp_counter: string }>(
      `SELECT last_totp_counter FROM identity_api.user_totp_credentials WHERE user_id = $1`,
      [account.userId],
    );
    const token = await nextAcceptedTotp(
      enrollment.secret,
      BigInt(stored?.rows[0]?.last_totp_counter ?? '-1'),
    );
    const verified = await account.agent
      .post('/auth/mfa/totp/verify')
      .set('Host', issuerHost)
      .send({ challengeId: login.body.challengeId, token });
    expect([302, 303]).toContain(verified.status);
    const authorizationUrl = verified.headers.location;
    if (!authorizationUrl) throw new Error('OIDC MFA completion did not resume authorization');

    // Completing the login interaction returns to the original authorization
    // request first. oidc-provider then creates and redirects to the consent
    // interaction, so follow that redirect before checking the consent prompt.
    const authorizationResume = new URL(authorizationUrl, oidc.issuer);
    const consentRedirect = await account.agent
      .get(`${authorizationResume.pathname}${authorizationResume.search}`)
      .set('Host', issuerHost);
    expect([302, 303]).toContain(consentRedirect.status);
    const consentUrl = consentRedirect.headers.location;
    if (!consentUrl) throw new Error('OIDC authorization did not redirect to consent');
    const consentPath = new URL(consentUrl, oidc.issuer);
    const consent = await account.agent
      .get(`${consentPath.pathname}${consentPath.search}`)
      .set('Host', issuerHost);
    expect(consent.status).toBe(200);
    expect(consent.body.prompt).toBe('consent');
  });

  it('does not let Google sign-in bypass MFA for an enrolled account', async () => {
    if (!pool || !redis) throw new Error('Isolated test infrastructure is unavailable');
    const identity: GoogleIdentityClaims = {
      subject: randomUUID(),
      email: `mfa-google-${randomUUID()}@example.test`,
      emailVerified: true,
    };
    const googleClient: GoogleOidcClient = {
      authorizationUrl: async ({ state }) => `https://accounts.google.test/auth?state=${state}`,
      completeAuthorization: async () => identity,
    };
    const googleApp = createApp({
      pool,
      redis,
      rateLimitKeySecret: randomUUID(),
      mfaEncryptionKey,
      googleOidcClient: googleClient,
      googleRedirectUri: 'http://localhost:3005/auth/google/callback',
      emailProvider,
    });
    const agent = request.agent(googleApp);

    const begin = await agent.get('/auth/google').set('Host', 'localhost:3005');
    expect(begin.status).toBe(302);
    const beginLocation = begin.headers.location;
    if (!beginLocation) throw new Error('Google sign-in did not redirect to its provider');
    const state = new URL(beginLocation).searchParams.get('state');
    if (!state) throw new Error('Google sign-in redirect did not include state');
    const firstCallback = await agent
      .get('/auth/google/callback')
      .set('Host', 'localhost:3005')
      .query({ code: 'synthetic-code', state });
    expect(firstCallback.status).toBe(200);
    const userId = firstCallback.body.userId as string;

    const enrollment = await enrollTotp(agent, userId);
    await agent.post('/auth/logout');
    const secondBegin = await agent.get('/auth/google').set('Host', 'localhost:3005');
    const secondBeginLocation = secondBegin.headers.location;
    if (!secondBeginLocation) throw new Error('Google sign-in did not redirect on retry');
    const secondState = new URL(secondBeginLocation).searchParams.get('state');
    if (!secondState) throw new Error('Google sign-in retry did not include state');
    const secondCallback = await agent
      .get('/auth/google/callback')
      .set('Host', 'localhost:3005')
      .query({ code: 'synthetic-code', state: secondState });
    expect(secondCallback.status).toBe(202);
    expect(secondCallback.body.mfaRequired).toBe(true);
    expect(String(secondCallback.headers['set-cookie'])).not.toContain('identity_session=');

    const code = await nextAcceptedTotp(enrollment.secret, enrollment.counter);
    const completed = await agent
      .post('/auth/mfa/totp/verify')
      .send({ challengeId: secondCallback.body.challengeId, token: code });
    expect(completed.status).toBe(200);
    expect(completed.body.userId).toBe(userId);
    expect((await agent.get('/auth/session')).status).toBe(200);
  });
});
