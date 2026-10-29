import { randomUUID } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { IdentityRepository } from '../src/identity/identity.repository.js';
import { createPostgresPool } from '../src/infrastructure/postgres/pool.js';
import { runMigrations } from '../src/infrastructure/postgres/migrations.js';
import { createRedisClient } from '../src/infrastructure/redis/client.js';
import { OrganizationRepository } from '../src/organizations/organization.repository.js';
import { ApiSessionService } from '../src/sessions/session.service.js';
import { readTestInfrastructureConfig } from './helpers/testInfrastructure.js';

const testConfig = readTestInfrastructureConfig();

describe.skipIf(!testConfig)('organization authorization integration', () => {
  const pool = testConfig ? createPostgresPool(testConfig.postgres) : undefined;
  const redis = testConfig ? createRedisClient(testConfig.redis) : undefined;
  const identities = pool ? new IdentityRepository(pool) : undefined;
  const organizations = pool ? new OrganizationRepository(pool) : undefined;
  const sessions = pool && redis ? new ApiSessionService(pool, redis) : undefined;
  const app =
    pool && redis ? createApp({ pool, redis, rateLimitKeySecret: randomUUID() }) : createApp();

  beforeAll(async () => {
    if (!pool || !redis) throw new Error('Isolated HTTP test infrastructure is unavailable');
    await runMigrations(pool);
    await redis.connect();
  });

  afterAll(async () => {
    await Promise.allSettled([pool?.end(), redis?.quit()]);
  });

  async function newUser(): Promise<{ id: string; cookie: string }> {
    if (!identities || !sessions) throw new Error('Organization test dependencies are unavailable');
    const account = await identities.createAccount({
      email: `organization-${randomUUID()}@example.test`,
      emailVerified: true,
    });
    return {
      id: account.id,
      cookie: `identity_session=${await sessions.create(account.id)}`,
    };
  }

  it('allows an active organization member to read that organization resources', async () => {
    if (!organizations) throw new Error('Organization repository is unavailable');
    const owner = await newUser();
    const member = await newUser();
    const created = await request(app)
      .post('/organizations')
      .set('Cookie', owner.cookie)
      .send({ name: 'Tenant Alpha', slug: `tenant-alpha-${randomUUID().slice(0, 8)}` });
    expect(created.status).toBe(201);

    const added = await request(app)
      .post(`/organizations/${created.body.id}/members`)
      .set('Cookie', owner.cookie)
      .send({ userId: member.id, role: 'member' });
    expect(added.status).toBe(201);
    expect(added.body.membership).toMatchObject({
      organizationId: created.body.id,
      userId: member.id,
      role: 'member',
      status: 'active',
    });

    const resources = await request(app)
      .get(`/organizations/${created.body.id}/resources`)
      .set('Cookie', member.cookie);
    expect(resources.status).toBe(200);
    expect(resources.body).toEqual({
      organizationId: created.body.id,
      organizationName: 'Tenant Alpha',
      resources: [],
    });
  });

  it('rejects a cross-organization resource access attempt with 403', async () => {
    if (!organizations) throw new Error('Organization repository is unavailable');
    const ownerA = await newUser();
    const member = await newUser();
    const ownerB = await newUser();
    const orgA = await organizations.createOrganization({
      name: 'Tenant A',
      slug: `tenant-a-${randomUUID().slice(0, 8)}`,
      ownerUserId: ownerA.id,
    });
    await organizations.addMember({
      organizationId: orgA.id,
      actorUserId: ownerA.id,
      userId: member.id,
      role: 'member',
    });
    const orgB = await organizations.createOrganization({
      name: 'Tenant B',
      slug: `tenant-b-${randomUUID().slice(0, 8)}`,
      ownerUserId: ownerB.id,
    });

    const response = await request(app)
      .get(`/organizations/${orgB.id}/resources`)
      .set('Cookie', member.cookie);
    expect(response.status).toBe(403);
    expect(response.body).toEqual({ error: 'Organization access denied.' });
  });

  it('rejects a user without organization membership with 403', async () => {
    const owner = await newUser();
    const outsider = await newUser();
    const organization = await request(app)
      .post('/organizations')
      .set('Cookie', owner.cookie)
      .send({ name: 'Private tenant', slug: `private-${randomUUID().slice(0, 8)}` });
    expect(organization.status).toBe(201);

    const response = await request(app)
      .get(`/organizations/${organization.body.id}/resources`)
      .set('Cookie', outsider.cookie);
    expect(response.status).toBe(403);
    expect(response.body).toEqual({ error: 'Organization access denied.' });
  });

  it('removes resource access immediately when membership is disabled and audits the change', async () => {
    const owner = await newUser();
    const member = await newUser();
    const organization = await request(app)
      .post('/organizations')
      .set('Cookie', owner.cookie)
      .send({ name: 'Disable tenant', slug: `disable-${randomUUID().slice(0, 8)}` });
    expect(organization.status).toBe(201);
    const added = await request(app)
      .post(`/organizations/${organization.body.id}/members`)
      .set('Cookie', owner.cookie)
      .send({ userId: member.id, role: 'member' });
    expect(added.status).toBe(201);

    const before = await request(app)
      .get(`/organizations/${organization.body.id}/resources`)
      .set('Cookie', member.cookie);
    expect(before.status).toBe(200);

    const disabled = await request(app)
      .patch(`/organizations/${organization.body.id}/members/${member.id}/status`)
      .set('Cookie', owner.cookie)
      .send({ status: 'disabled' });
    expect(disabled.status).toBe(200);
    expect(disabled.body.membership.status).toBe('disabled');

    const after = await request(app)
      .get(`/organizations/${organization.body.id}/resources`)
      .set('Cookie', member.cookie);
    expect(after.status).toBe(403);

    const audit = await request(app)
      .get(`/organizations/${organization.body.id}/audit`)
      .set('Cookie', owner.cookie);
    expect(audit.status).toBe(200);
    expect(audit.body.events.map((event: { eventType: string }) => event.eventType)).toEqual(
      expect.arrayContaining(['organization.created', 'membership.added', 'membership.disabled']),
    );
    expect(JSON.stringify(audit.body)).not.toMatch(/password|secret|token|email/i);
  });
});
