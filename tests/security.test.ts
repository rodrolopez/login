import { randomUUID } from 'node:crypto';
import request from 'supertest';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { createApp } from '../src/app.js';
import { AuthAttemptRateLimiter } from '../src/auth/auth-rate-limiter.js';
import { IdentityRepository } from '../src/identity/identity.repository.js';
import { createPostgresPool } from '../src/infrastructure/postgres/pool.js';
import { runMigrations } from '../src/infrastructure/postgres/migrations.js';
import { createRedisClient } from '../src/infrastructure/redis/client.js';
import { createOidcProvider, OIDC_MOUNT_PATH } from '../src/oidc/provider.js';
import { OrganizationRepository } from '../src/organizations/organization.repository.js';
import { ApiSessionService } from '../src/sessions/session.service.js';
import { readTestInfrastructureConfig } from './helpers/testInfrastructure.js';

const testConfig = readTestInfrastructureConfig();
const trustedOrigin = 'https://frontend.example.test';
const rateLimitSecret = randomUUID();

describe.skipIf(!testConfig)('adversarial security integration', () => {
  const pool = testConfig ? createPostgresPool(testConfig.postgres) : undefined;
  const redis = testConfig ? createRedisClient(testConfig.redis) : undefined;
  const repository = pool ? new IdentityRepository(pool) : undefined;
  const organizations = pool ? new OrganizationRepository(pool) : undefined;
  const sessions = pool && redis ? new ApiSessionService(pool, redis) : undefined;
  const oidc =
    pool && redis
      ? createOidcProvider({ pool, redis, issuer: 'http://127.0.0.1:3005/oidc' })
      : undefined;
  const app =
    pool && redis && oidc
      ? createApp({
          pool,
          redis,
          rateLimitKeySecret: rateLimitSecret,
          oidcProvider: oidc.provider,
          corsAllowedOrigins: [trustedOrigin],
        })
      : createApp();

  beforeAll(async () => {
    if (!pool || !redis) throw new Error('Isolated security test infrastructure is unavailable');
    await runMigrations(pool);
    await redis.connect();
  });

  afterAll(async () => {
    await Promise.allSettled([pool?.end(), redis?.quit()]);
  });

  afterEach(() => vi.unstubAllEnvs());

  async function newUser(): Promise<{ id: string; cookie: string }> {
    if (!repository || !sessions) throw new Error('Identity test dependencies are unavailable');
    const account = await repository.createAccount({
      email: `security-${randomUUID()}@example.test`,
      emailVerified: true,
    });
    return {
      id: account.id,
      cookie: `identity_session=${await sessions.create(account.id)}`,
    };
  }

  it('sets security headers, suppresses framework disclosure, and switches HSTS on in production', async () => {
    const development = await request(app).get('/health');
    expect(development.status).toBe(200);
    expect(development.headers['x-content-type-options']).toBe('nosniff');
    expect(development.headers['x-frame-options']).toBe('DENY');
    expect(development.headers['content-security-policy']).toContain("default-src 'none'");
    expect(development.headers['referrer-policy']).toBe('no-referrer');
    expect(development.headers['permissions-policy']).toContain('camera=()');
    expect(development.headers['strict-transport-security']).toBeUndefined();
    expect(development.headers['x-powered-by']).toBeUndefined();

    vi.stubEnv('NODE_ENV', 'production');
    const production = await request(app).get('/health');
    expect(production.headers['strict-transport-security']).toBe(
      'max-age=31536000; includeSubDomains',
    );
  });

  it('allows only configured CORS origins and preflight methods/headers', async () => {
    const allowedPreflight = await request(app)
      .options('/auth/login')
      .set('Origin', trustedOrigin)
      .set('Access-Control-Request-Method', 'POST')
      .set('Access-Control-Request-Headers', 'content-type, accept-language');
    expect(allowedPreflight.status).toBe(204);
    expect(allowedPreflight.headers['access-control-allow-origin']).toBe(trustedOrigin);
    expect(allowedPreflight.headers['access-control-allow-credentials']).toBe('true');

    const disallowedOrigin = await request(app)
      .post('/auth/login')
      .set('Origin', 'https://attacker.example')
      .send({ email: 'victim@example.test', password: 'not a real password' });
    expect(disallowedOrigin.status).toBe(403);
    expect(disallowedOrigin.headers['access-control-allow-origin']).toBeUndefined();

    const disallowedHeader = await request(app)
      .options('/auth/login')
      .set('Origin', trustedOrigin)
      .set('Access-Control-Request-Method', 'POST')
      .set('Access-Control-Request-Headers', 'x-untrusted-header');
    expect(disallowedHeader.status).toBe(403);
  });

  it('rejects SQL injection shaped input and leaves identity rows intact', async () => {
    if (!pool || !repository) throw new Error('PostgreSQL is unavailable');
    const owner = await newUser();
    const markerEmail = `sqli-marker-${randomUUID()}@example.test`;
    const marker = await repository.createAccount({ email: markerEmail, emailVerified: true });
    const before = await repository.findLoginCredentialByEmail(markerEmail);
    const injectedLogin = await request(app)
      .post('/auth/login')
      .send({ email: "' OR 1=1 --@example.test", password: 'not a real password' });
    expect(injectedLogin.status).toBe(400);

    const injectedSlug = await request(app)
      .post('/organizations')
      .set('Cookie', owner.cookie)
      .send({ name: 'SQL injection probe', slug: "safe'); DROP TABLE users; --" });
    expect(injectedSlug.status).toBe(400);

    const directLookup = await repository.findLoginCredentialByEmail("' OR 1=1 --");
    expect(directLookup).toBeUndefined();
    const after = await repository.findLoginCredentialByEmail(markerEmail);
    expect(after).toEqual(before);
    expect(await repository.findAccountById(marker.id)).toBeDefined();
    await expect(pool.query('SELECT 1 FROM identity_api.users LIMIT 1')).resolves.toBeDefined();
  });

  it('enforces pair and IP rate limits during bursts, including rotated email values', async () => {
    if (!redis) throw new Error('Redis is unavailable');
    const loginBurst = await Promise.all(
      Array.from({ length: 20 }, () =>
        request(app)
          .post('/auth/login')
          .send({
            email: `burst-${rateLimitSecret}@example.test`,
            password: 'not a real password',
          }),
      ),
    );
    expect(loginBurst.some((response) => response.status === 429)).toBe(true);

    const limiter = new AuthAttemptRateLimiter(
      redis,
      randomUUID(),
      5,
      60,
      60_000,
      `security-burst-${randomUUID()}`,
    );
    const rotatedEmailBurst = await Promise.all(
      Array.from({ length: 65 }, (_, index) =>
        limiter.consume('198.51.100.77', `rotated-${index}-${randomUUID()}@example.test`),
      ),
    );
    expect(rotatedEmailBurst.filter((result) => result.allowed)).toHaveLength(60);
    expect(rotatedEmailBurst.filter((result) => !result.allowed)).toHaveLength(5);
  });

  it('rejects cross-tenant IDOR and unauthorized membership changes for authenticated users', async () => {
    if (!organizations) throw new Error('Organization repository is unavailable');
    const ownerA = await newUser();
    const ownerB = await newUser();
    const member = await newUser();
    const orgA = await request(app)
      .post('/organizations')
      .set('Cookie', ownerA.cookie)
      .send({ name: 'Security Tenant A', slug: `security-a-${randomUUID().slice(0, 8)}` });
    const orgB = await request(app)
      .post('/organizations')
      .set('Cookie', ownerB.cookie)
      .send({ name: 'Security Tenant B', slug: `security-b-${randomUUID().slice(0, 8)}` });
    expect(orgA.status).toBe(201);
    expect(orgB.status).toBe(201);
    const membership = await request(app)
      .post(`/organizations/${orgA.body.id}/members`)
      .set('Cookie', ownerA.cookie)
      .send({ userId: member.id, role: 'member' });
    expect(membership.status).toBe(201);

    const crossTenant = await request(app)
      .get(`/organizations/${orgB.body.id}/resources`)
      .set('Cookie', member.cookie);
    expect(crossTenant.status).toBe(403);

    const roleChange = await request(app)
      .patch(`/organizations/${orgA.body.id}/members/${ownerA.id}/role`)
      .set('Cookie', member.cookie)
      .send({ role: 'admin' });
    expect(roleChange.status).toBe(403);

    const manipulatedId = await request(app)
      .get('/organizations/00000000-0000-0000-0000-000000000000/resources')
      .set('Cookie', member.cookie);
    expect(manipulatedId.status).toBe(403);
  });

  it('rejects oversized and malformed bodies without leaking parser diagnostics', async () => {
    const oversized = await request(app)
      .post('/auth/login')
      .set('Content-Type', 'application/json')
      .send(JSON.stringify({ email: 'large@example.test', password: 'x'.repeat(40 * 1024) }));
    expect(oversized.status).toBe(413);
    expect(oversized.body).toEqual({ error: 'El cuerpo de la solicitud es demasiado grande.' });
    expect(JSON.stringify(oversized.body)).not.toMatch(/stack|body-parser|entity/i);

    const malformed = await request(app)
      .post('/auth/login')
      .set('Content-Type', 'application/json')
      .send('{"email":');
    expect(malformed.status).toBe(400);
    expect(malformed.body).toEqual({ error: 'La solicitud contiene datos inválidos.' });
    expect(JSON.stringify(malformed.body)).not.toMatch(/stack|syntaxerror|entity/i);
  });

  it('limits OIDC client CORS to registered redirect origins and keeps public metadata uncredentialed', async () => {
    if (!oidc) throw new Error('OIDC provider is unavailable');
    const metadata = await request(app)
      .get(`${OIDC_MOUNT_PATH}/.well-known/openid-configuration`)
      .set('Host', '127.0.0.1:3005')
      .set('Origin', 'https://untrusted-reader.example');
    expect(metadata.status).toBe(200);
    expect(metadata.headers['access-control-allow-credentials']).toBeUndefined();

    const invalidClientOrigin = await request(app)
      .post(`${OIDC_MOUNT_PATH}/token`)
      .set('Host', '127.0.0.1:3005')
      .set('Origin', 'https://untrusted-reader.example')
      .type('form')
      .send({
        grant_type: 'authorization_code',
        code: 'not-a-real-code',
        redirect_uri: 'http://127.0.0.1:4100/callback',
        client_id: 'identity-public-test-client',
        code_verifier: 'not-a-real-verifier',
      });
    expect(invalidClientOrigin.status).toBe(400);
    expect(invalidClientOrigin.headers['access-control-allow-origin']).toBeUndefined();

    const registeredClientOrigin = await request(app)
      .post(`${OIDC_MOUNT_PATH}/token`)
      .set('Host', '127.0.0.1:3005')
      .set('Origin', 'http://127.0.0.1:4100')
      .type('form')
      .send({
        grant_type: 'authorization_code',
        code: 'not-a-real-code',
        redirect_uri: 'http://127.0.0.1:4100/callback',
        client_id: 'identity-public-test-client',
        code_verifier: 'not-a-real-verifier',
      });
    expect(registeredClientOrigin.status).toBe(400);
    expect(registeredClientOrigin.headers['access-control-allow-origin']).toBe(
      'http://127.0.0.1:4100',
    );
  });
});
