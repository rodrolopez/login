import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { IdentityRepository } from '../src/identity/identity.repository.js';
import { createPostgresPool } from '../src/infrastructure/postgres/pool.js';
import { runMigrations } from '../src/infrastructure/postgres/migrations.js';
import { readTestInfrastructureConfig } from './helpers/testInfrastructure.js';

const testConfig = readTestInfrastructureConfig();
const syntheticArgon2idHash =
  '$argon2id$v=19$m=65536,p=1,t=3$c29tZXNhbHQxMjM0NTY3OA$YW5vdGhlcnN5bnRoZXRpY2RpZ2VzdA';

describe.skipIf(!testConfig)('identity repository integration', () => {
  const pool = testConfig ? createPostgresPool(testConfig.postgres) : undefined;
  const repository = pool ? new IdentityRepository(pool) : undefined;

  beforeAll(async () => {
    if (!pool) throw new Error('Isolated PostgreSQL test pool is unavailable');
    await runMigrations(pool);
  });

  afterAll(async () => {
    await pool?.end();
  });

  it('creates a pending account with normalized email and an encoded password hash', async () => {
    if (!repository) throw new Error('Identity repository is unavailable');
    const email = `User-${randomUUID()}@Example.Test`;
    const account = await repository.createAccount({ email, passwordHash: syntheticArgon2idHash });

    expect(account.id).toMatch(/^[0-9a-f-]{36}$/i);
    expect(account.status).toBe('pending');
    expect(account.emails).toHaveLength(1);
    expect(account.emails[0]).toMatchObject({ email: email.toLowerCase(), isPrimary: true });
    expect(account.emails[0]?.verifiedAt).toBeNull();
    expect(await repository.findPasswordCredential(account.id)).toMatchObject({
      userId: account.id,
      passwordHash: syntheticArgon2idHash,
    });
    const primaryEmail = account.emails[0];
    if (!primaryEmail) throw new Error('Primary email was not created');
    expect(await repository.verifyEmail(account.id, primaryEmail.id)).toBe(true);
    const verified = await repository.findAccountById(account.id);
    expect(verified?.emails[0]?.verifiedAt).toBeInstanceOf(Date);
  });

  it('rejects duplicate email addresses regardless of letter case', async () => {
    if (!repository) throw new Error('Identity repository is unavailable');
    const email = `unique-${randomUUID()}@example.test`;
    await repository.createAccount({ email });

    await expect(repository.createAccount({ email: email.toUpperCase() })).rejects.toMatchObject({
      code: '23505',
    });
  });

  it('rejects external identities that reference a missing account', async () => {
    if (!pool || !repository) throw new Error('Identity repository is unavailable');
    const missingUserId = randomUUID();
    await expect(
      repository.linkExternalIdentity({
        userId: missingUserId,
        provider: 'google',
        issuer: 'https://accounts.google.com',
        subject: randomUUID(),
      }),
    ).rejects.toThrow('Account is unavailable for identity linking');
    await expect(
      pool.query(
        `INSERT INTO identity_api.external_identities (user_id, provider, issuer, subject)
         VALUES ($1, 'google', 'https://accounts.google.com', $2)`,
        [missingUserId, randomUUID()],
      ),
    ).rejects.toMatchObject({ code: '23503' });
  });

  it('enforces unique external provider subjects across accounts', async () => {
    if (!repository) throw new Error('Identity repository is unavailable');
    const first = await repository.createAccount({
      email: `google-a-${randomUUID()}@example.test`,
    });
    const second = await repository.createAccount({
      email: `google-b-${randomUUID()}@example.test`,
    });
    const issuer = 'https://accounts.google.com';
    const subject = randomUUID();
    await repository.linkExternalIdentity({
      userId: first.id,
      provider: 'google',
      issuer,
      subject,
    });

    await expect(
      repository.linkExternalIdentity({ userId: second.id, provider: 'google', issuer, subject }),
    ).rejects.toMatchObject({ code: '23505' });
  });

  it('preserves disabled account state and its data for reversible deactivation', async () => {
    if (!repository) throw new Error('Identity repository is unavailable');
    const account = await repository.createAccount({
      email: `disabled-${randomUUID()}@example.test`,
      passwordHash: syntheticArgon2idHash,
    });

    expect(await repository.disableAccount(account.id)).toBe(true);
    const disabled = await repository.findAccountById(account.id);
    expect(disabled?.status).toBe('disabled');
    expect(disabled?.disabledAt).toBeInstanceOf(Date);
    expect(disabled?.emails).toHaveLength(1);
    expect(await repository.findPasswordCredential(account.id)).toBeDefined();
  });

  it('anonymizes personal identity data before allowing physical deletion', async () => {
    if (!repository) throw new Error('Identity repository is unavailable');
    const account = await repository.createAccount({
      email: `erase-${randomUUID()}@example.test`,
      passwordHash: syntheticArgon2idHash,
    });
    await repository.linkExternalIdentity({
      userId: account.id,
      provider: 'google',
      issuer: 'https://accounts.google.com',
      subject: randomUUID(),
    });

    expect(await repository.deleteAnonymizedAccountPermanently(account.id)).toBe(false);
    expect(await repository.anonymizeAccount(account.id)).toBe(true);
    expect(await repository.anonymizeAccount(account.id)).toBe(true);
    const anonymized = await repository.findAccountById(account.id);
    expect(anonymized?.status).toBe('anonymized');
    expect(anonymized?.anonymizedAt).toBeInstanceOf(Date);
    expect(anonymized?.emails).toEqual([]);
    expect(await repository.findPasswordCredential(account.id)).toBeUndefined();
    await expect(
      repository.linkExternalIdentity({
        userId: account.id,
        provider: 'google',
        issuer: 'https://accounts.google.com',
        subject: randomUUID(),
      }),
    ).rejects.toThrow('Account is unavailable for identity linking');
    expect(await repository.deleteAnonymizedAccountPermanently(account.id)).toBe(true);
    expect(await repository.findAccountById(account.id)).toBeUndefined();
  });

  it('rejects plaintext password values at the repository boundary', async () => {
    if (!pool || !repository) throw new Error('Identity repository is unavailable');
    await expect(
      repository.createAccount({
        email: `plaintext-${randomUUID()}@example.test`,
        passwordHash: 'not-a-hash',
      }),
    ).rejects.toThrow('Argon2id encoded hash');

    const account = await repository.createAccount({
      email: `invalid-hash-${randomUUID()}@example.test`,
    });
    await expect(
      pool.query(
        `INSERT INTO identity_api.password_credentials (user_id, password_hash)
         VALUES ($1, '$argon2id$invalid')`,
        [account.id],
      ),
    ).rejects.toMatchObject({ code: '23514' });
  });
});
