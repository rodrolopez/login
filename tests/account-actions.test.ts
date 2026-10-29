import { createHash, randomUUID } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { createPostgresPool } from '../src/infrastructure/postgres/pool.js';
import { runMigrations } from '../src/infrastructure/postgres/migrations.js';
import { createRedisClient } from '../src/infrastructure/redis/client.js';
import { TestEmailProvider } from '../src/email/email-provider.js';
import { createOidcProvider, PUBLIC_TEST_CLIENT_ID } from '../src/oidc/provider.js';
import { readTestInfrastructureConfig } from './helpers/testInfrastructure.js';

const testConfig = readTestInfrastructureConfig();
const oldPassword = `Old password ${randomUUID()}!`;
const newPassword = `New password ${randomUUID()}!`;

describe.skipIf(!testConfig)('email verification and password recovery HTTP integration', () => {
  const pool = testConfig ? createPostgresPool(testConfig.postgres) : undefined;
  const redis = testConfig ? createRedisClient(testConfig.redis) : undefined;
  const emailProvider = new TestEmailProvider();
  const oidc =
    pool && redis
      ? createOidcProvider({ pool, redis, issuer: 'http://127.0.0.1:3005/oidc' })
      : undefined;
  const app =
    pool && redis && oidc
      ? createApp({
          pool,
          redis,
          rateLimitKeySecret: randomUUID(),
          emailProvider,
          oidcProvider: oidc.provider,
        })
      : createApp();

  beforeAll(async () => {
    if (!pool || !redis) throw new Error('Isolated action test infrastructure is unavailable');
    await runMigrations(pool);
    await redis.connect();
  });

  afterAll(async () => {
    await Promise.allSettled([pool?.end(), redis?.quit()]);
  });

  async function registerUnverified(email = `verify-${randomUUID()}@example.test`) {
    const registered = await request(app)
      .post('/auth/register')
      .send({ email, password: oldPassword });
    expect(registered.status).toBe(201);
    expect(registered.body).toEqual({ userId: expect.any(String) });
    expect(JSON.stringify(registered.body)).not.toContain('token');
    const delivery = emailProvider.takeLast('email_verification');
    if (!delivery) throw new Error('Test verification email was not captured');
    expect(delivery.recipient).toBe(email.toLowerCase());
    return { userId: registered.body.userId as string, email, token: delivery.token };
  }

  async function verifyToken(token: string) {
    return request(app).post('/auth/email/verification/confirm').send({ token });
  }

  it('verifies an email once, activates the account, and permits login only after verification', async () => {
    const account = await registerUnverified();
    const beforeVerification = await request(app)
      .post('/auth/login')
      .send({ email: account.email, password: oldPassword });
    expect(beforeVerification.status).toBe(401);
    expect(beforeVerification.body).toEqual({ error: 'Credenciales inválidas.' });

    if (!pool) throw new Error('PostgreSQL is unavailable');
    const stored = await pool.query<{ token_hash: string; purpose: string }>(
      `SELECT token_hash, purpose FROM identity_api.account_action_tokens
       WHERE user_id = $1 AND purpose = 'email_verification'`,
      [account.userId],
    );
    expect(stored.rows).toHaveLength(1);
    expect(stored.rows[0]).toEqual({
      token_hash: createHash('sha256').update(account.token).digest('hex'),
      purpose: 'email_verification',
    });
    expect(stored.rows[0]?.token_hash).not.toBe(account.token);

    const verified = await verifyToken(account.token);
    expect(verified.status).toBe(200);
    expect(verified.body).toEqual({ message: 'Correo electrónico verificado.' });
    expect((await verifyToken(account.token)).status).toBe(400);

    const login = await request(app)
      .post('/auth/login')
      .send({ email: account.email, password: oldPassword });
    expect(login.status).toBe(200);
  });

  it('returns identical generic verification and recovery request responses for known and unknown email', async () => {
    const account = await registerUnverified();
    const knownVerification = await request(app)
      .post('/auth/email/verification/request')
      .send({ email: account.email });
    const unknownVerification = await request(app)
      .post('/auth/email/verification/request')
      .send({ email: `missing-${randomUUID()}@example.test` });
    expect(knownVerification.status).toBe(202);
    expect(unknownVerification.status).toBe(knownVerification.status);
    expect(unknownVerification.body).toEqual(knownVerification.body);
    expect(knownVerification.body).toEqual({
      message:
        'Si la cuenta puede realizar esta operación, recibirá instrucciones por correo electrónico.',
    });

    const token = emailProvider.takeLast('email_verification')?.token;
    expect(token).toBeTruthy();
    if (!token) throw new Error('Verification email was not captured');
    expect((await verifyToken(account.token)).status).toBe(400);
    expect((await verifyToken(token)).status).toBe(200);

    const knownRecovery = await request(app)
      .post('/auth/password/recovery/request')
      .send({ email: account.email });
    const unknownRecovery = await request(app)
      .post('/auth/password/recovery/request')
      .send({ email: `missing-${randomUUID()}@example.test` });
    expect(knownRecovery.status).toBe(202);
    expect(unknownRecovery.status).toBe(knownRecovery.status);
    expect(unknownRecovery.body).toEqual(knownRecovery.body);
  });

  it('rejects expired, altered, and wrong-purpose tokens', async () => {
    if (!pool) throw new Error('PostgreSQL is unavailable');
    const expiredAccount = await registerUnverified();
    const expiredHash = createHash('sha256').update(expiredAccount.token).digest('hex');
    await pool.query(
      `UPDATE identity_api.account_action_tokens
       SET created_at = now() - interval '1 minute', expires_at = now() - interval '1 second'
       WHERE token_hash = $1`,
      [expiredHash],
    );
    expect((await verifyToken(expiredAccount.token)).status).toBe(400);

    const alteredAccount = await registerUnverified();
    const altered = `${alteredAccount.token.slice(0, -1)}${alteredAccount.token.endsWith('A') ? 'B' : 'A'}`;
    expect((await verifyToken(altered)).status).toBe(400);

    const wrongPurpose = await registerUnverified();
    const wrongPurposeResponse = await request(app)
      .post('/auth/password/recovery/confirm')
      .send({ token: wrongPurpose.token, password: newPassword });
    expect(wrongPurposeResponse.status).toBe(400);
    expect((await verifyToken(wrongPurpose.token)).status).toBe(200);

    const expiredRecoveryRequest = await request(app)
      .post('/auth/password/recovery/request')
      .send({ email: wrongPurpose.email });
    expect(expiredRecoveryRequest.status).toBe(202);
    const expiredRecoveryToken = emailProvider.takeLast('password_recovery')?.token;
    if (!expiredRecoveryToken) throw new Error('Test recovery email was not captured');
    await pool.query(
      `UPDATE identity_api.account_action_tokens
       SET created_at = now() - interval '1 minute', expires_at = now() - interval '1 second'
       WHERE token_hash = $1`,
      [createHash('sha256').update(expiredRecoveryToken).digest('hex')],
    );
    const expiredRecovery = await request(app)
      .post('/auth/password/recovery/confirm')
      .send({ token: expiredRecoveryToken, password: newPassword });
    expect(expiredRecovery.status).toBe(400);
  });

  it('resets a password once and revokes API sessions, OIDC refresh tokens, and grants', async () => {
    if (!oidc || !pool || !redis) throw new Error('Recovery infrastructure is unavailable');
    const agent = request.agent(app);
    const account = await registerUnverified(`recovery-${randomUUID()}@example.test`);
    expect(
      (await agent.post('/auth/email/verification/confirm').send({ token: account.token })).status,
    ).toBe(200);
    const login = await agent
      .post('/auth/login')
      .send({ email: account.email, password: oldPassword });
    expect(login.status).toBe(200);
    expect((await agent.get('/auth/session')).status).toBe(200);

    const client = await oidc.provider.Client.find(PUBLIC_TEST_CLIENT_ID);
    if (!client) throw new Error('OIDC test client is unavailable');
    const grant = new oidc.provider.Grant({ accountId: account.userId, clientId: client.clientId });
    grant.addOIDCScope(['openid', 'email', 'offline_access']);
    const grantId = await grant.save();
    const refreshToken = new oidc.provider.RefreshToken({
      accountId: account.userId,
      client,
      grantId,
      gty: 'authorization_code',
      scope: 'openid email offline_access',
    });
    const rawRefreshToken = await refreshToken.save();

    const knownRequest = await request(app)
      .post('/auth/password/recovery/request')
      .send({ email: account.email });
    const unknownRequest = await request(app)
      .post('/auth/password/recovery/request')
      .send({ email: `unknown-${randomUUID()}@example.test` });
    expect(knownRequest.status).toBe(202);
    expect(unknownRequest.status).toBe(knownRequest.status);
    expect(unknownRequest.body).toEqual(knownRequest.body);
    const recoveryEmail = emailProvider.takeLast('password_recovery');
    if (!recoveryEmail) throw new Error('Test recovery email was not captured');
    const storedRecoveryToken = await pool.query<{ token_hash: string }>(
      `SELECT token_hash FROM identity_api.account_action_tokens
       WHERE user_id = $1 AND purpose = 'password_recovery'`,
      [account.userId],
    );
    expect(storedRecoveryToken.rows).toHaveLength(1);
    expect(storedRecoveryToken.rows[0]?.token_hash).toBe(
      createHash('sha256').update(recoveryEmail.token).digest('hex'),
    );

    expect((await verifyToken(recoveryEmail.token)).status).toBe(400);
    const recovered = await agent
      .post('/auth/password/recovery/confirm')
      .send({ token: recoveryEmail.token, password: newPassword });
    expect(recovered.status).toBe(200);
    expect(recovered.body).toEqual({
      message: 'Contraseña actualizada. Iniciá sesión nuevamente.',
    });
    expect((await agent.get('/auth/session')).status).toBe(401);
    expect(await oidc.provider.RefreshToken.find(rawRefreshToken)).toBeUndefined();
    expect(
      (await pool.query('SELECT 1 FROM identity_api.oidc_grants WHERE grant_id = $1', [grantId]))
        .rowCount,
    ).toBe(0);

    const replay = await request(app)
      .post('/auth/password/recovery/confirm')
      .send({ token: recoveryEmail.token, password: `Another password ${randomUUID()}!` });
    expect(replay.status).toBe(400);
    expect(
      (await request(app).post('/auth/login').send({ email: account.email, password: oldPassword }))
        .status,
    ).toBe(401);
    expect(
      (await request(app).post('/auth/login').send({ email: account.email, password: newPassword }))
        .status,
    ).toBe(200);
  });
});
