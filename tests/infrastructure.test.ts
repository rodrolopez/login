import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Redis } from 'ioredis';
import { readTestInfrastructureConfig } from './helpers/testInfrastructure.js';
import { createPostgresPool, withTransaction } from '../src/infrastructure/postgres/pool.js';
import { runMigrations } from '../src/infrastructure/postgres/migrations.js';
import { createRedisClient, redisReconnectDelay } from '../src/infrastructure/redis/client.js';
import { readGoogleConfig, readInfrastructureConfig } from '../src/infrastructure/config.js';

const testConfig = readTestInfrastructureConfig();

describe.skipIf(!testConfig)('isolated infrastructure integration', () => {
  const pool = testConfig ? createPostgresPool(testConfig.postgres) : undefined;
  const redis: Redis | undefined = testConfig ? createRedisClient(testConfig.redis) : undefined;

  beforeAll(async () => {
    if (!pool || !redis) {
      throw new Error('Isolated test infrastructure is unavailable');
    }
    await Promise.all([pool.query('SELECT 1'), redis.connect()]);
  });

  afterAll(async () => {
    await Promise.allSettled([pool?.end(), redis?.quit()]);
  });

  it('applies the initial schema migration idempotently', async () => {
    if (!pool) throw new Error('Isolated PostgreSQL test pool is unavailable');

    const first = await runMigrations(pool);
    const second = await runMigrations(pool);

    expect(first.applied.length + first.alreadyApplied).toBe(7);
    expect(second.applied).toEqual([]);
    expect(second.alreadyApplied).toBeGreaterThanOrEqual(1);
    const migration = await pool.query<{ version: string }>(
      "SELECT version FROM public.schema_migrations WHERE version = '0001'",
    );
    expect(migration.rows).toHaveLength(1);
    const schema = await pool.query<{ schema_name: string }>(
      `SELECT schema_name FROM information_schema.schemata WHERE schema_name = 'identity_api'`,
    );
    expect(schema.rows).toHaveLength(1);
  });

  it('commits successful PostgreSQL transactions and rolls back failures', async () => {
    if (!pool) throw new Error('Isolated PostgreSQL test pool is unavailable');

    const value = await withTransaction(pool, async (client) => {
      const result = await client.query<{ value: number }>('SELECT $1::integer AS value', [42]);
      return result.rows[0]?.value;
    });
    expect(value).toBe(42);

    const tableName = `rollback_probe_${randomUUID().replaceAll('-', '')}`;
    await expect(
      withTransaction(pool, async (client) => {
        await client.query(`CREATE TEMP TABLE ${tableName} (value integer)`);
        throw new Error('synthetic rollback probe');
      }),
    ).rejects.toThrow('synthetic rollback probe');

    const result = await pool.query<{ relation: string | null }>(
      'SELECT to_regclass($1) AS relation',
      [`pg_temp.${tableName}`],
    );
    expect(result.rows[0]?.relation).toBeNull();
  });

  it('connects to Redis and confines test writes to the dedicated database index', async () => {
    if (!redis) throw new Error('Isolated Redis test client is unavailable');

    const key = `identity-api:test:${randomUUID()}`;
    try {
      expect(await redis.ping()).toBe('PONG');
      expect(await redis.set(key, 'synthetic', 'EX', 10, 'NX')).toBe('OK');
      expect(await redis.get(key)).toBe('synthetic');
    } finally {
      await redis.del(key);
    }
  });
});

describe('test infrastructure safety guard', () => {
  it('does not reuse application database settings when test settings are absent', () => {
    expect(readTestInfrastructureConfig({ PGDATABASE: 'production' } as NodeJS.ProcessEnv)).toBe(
      undefined,
    );
  });

  it('rejects a non-test database or non-loopback host', () => {
    expect(() =>
      readTestInfrastructureConfig({
        TEST_PGHOST: 'db.example.test',
        TEST_PGPORT: '5432',
        TEST_PGDATABASE: 'identity_api',
        TEST_PGUSER: 'identity_test',
        TEST_PGPASSWORD: 'synthetic',
        TEST_REDIS_HOST: '127.0.0.1',
        TEST_REDIS_PORT: '6380',
        TEST_REDIS_DB: '15',
      }),
    ).toThrow('loopback host');
  });

  it('caps Redis reconnection delays', () => {
    expect(redisReconnectDelay(1)).toBe(200);
    expect(redisReconnectDelay(5)).toBe(1_000);
    expect(redisReconnectDelay(20)).toBe(2_000);
  });
});

describe('Google configuration validation', () => {
  it('keeps Google sign-in disabled when no credentials are provided', () => {
    expect(readGoogleConfig({})).toBeUndefined();
  });

  it('requires all credentials and a valid callback URI once configured', () => {
    expect(() => readGoogleConfig({ GOOGLE_CLIENT_ID: 'synthetic' })).toThrow(
      'Invalid Google OAuth configuration',
    );
    expect(
      readGoogleConfig({
        GOOGLE_CLIENT_ID: 'synthetic-client-id',
        GOOGLE_CLIENT_SECRET: 'synthetic-client-secret',
        GOOGLE_REDIRECT_URI: 'http://localhost:3005/auth/google/callback',
      }),
    ).toMatchObject({ redirectUri: 'http://localhost:3005/auth/google/callback' });
    expect(() =>
      readGoogleConfig({
        GOOGLE_CLIENT_ID: 'synthetic-client-id',
        GOOGLE_CLIENT_SECRET: 'synthetic-client-secret',
        GOOGLE_REDIRECT_URI: 'http://identity.example.test/auth/google/callback',
      }),
    ).toThrow('HTTPS outside local development');
  });
});

describe('CORS configuration validation', () => {
  const baseEnvironment = {
    PGDATABASE: 'identity_dev',
    PGUSER: 'identity_user',
    PGPASSWORD: 'synthetic-postgres-password',
    REDIS_PASSWORD: 'synthetic-redis-password',
  } as NodeJS.ProcessEnv;

  it('accepts exact origins and rejects wildcard, paths, and insecure production origins', () => {
    expect(
      readInfrastructureConfig({
        ...baseEnvironment,
        CORS_ALLOWED_ORIGINS: 'https://app.example.test,http://localhost:4100',
      }).corsAllowedOrigins,
    ).toEqual(['https://app.example.test', 'http://localhost:4100']);
    expect(() =>
      readInfrastructureConfig({ ...baseEnvironment, CORS_ALLOWED_ORIGINS: '*' }),
    ).toThrow('Invalid CORS origin configuration');
    expect(() =>
      readInfrastructureConfig({
        ...baseEnvironment,
        CORS_ALLOWED_ORIGINS: 'https://app.example.test/path',
      }),
    ).toThrow('Invalid CORS origin configuration');
    expect(() =>
      readInfrastructureConfig({
        ...baseEnvironment,
        NODE_ENV: 'production',
        CORS_ALLOWED_ORIGINS: 'http://app.example.test',
      }),
    ).toThrow('Invalid CORS origin configuration');
  });
});

describe('MFA encryption configuration', () => {
  const baseEnvironment = {
    PGDATABASE: 'identity_dev',
    PGUSER: 'identity_user',
    PGPASSWORD: 'synthetic-postgres-password',
    REDIS_PASSWORD: 'synthetic-redis-password',
  } as NodeJS.ProcessEnv;

  it('accepts an optional 32-byte hexadecimal key and rejects weak or malformed values', () => {
    const mfaEncryptionKey = 'a'.repeat(64);
    expect(
      readInfrastructureConfig({ ...baseEnvironment, MFA_ENCRYPTION_KEY: mfaEncryptionKey })
        .mfaEncryptionKey,
    ).toBe(mfaEncryptionKey);
    expect(readInfrastructureConfig(baseEnvironment).mfaEncryptionKey).toBeUndefined();
    expect(() =>
      readInfrastructureConfig({ ...baseEnvironment, MFA_ENCRYPTION_KEY: 'short' }),
    ).toThrow('Invalid MFA encryption key configuration');
  });
});
