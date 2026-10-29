import 'dotenv/config';
import type { RedisClientConfig } from '../../src/infrastructure/redis/client.js';
import type { PostgresPoolConfig } from '../../src/infrastructure/postgres/pool.js';

const requiredTestVariables = [
  'TEST_PGHOST',
  'TEST_PGPORT',
  'TEST_PGDATABASE',
  'TEST_PGUSER',
  'TEST_PGPASSWORD',
  'TEST_REDIS_HOST',
  'TEST_REDIS_PORT',
  'TEST_REDIS_DB',
] as const;

export interface TestInfrastructureConfig {
  postgres: PostgresPoolConfig;
  redis: RedisClientConfig;
}

export function readTestInfrastructureConfig(
  environment: NodeJS.ProcessEnv = process.env,
): TestInfrastructureConfig | undefined {
  const configured = requiredTestVariables.some((name) => environment[name] !== undefined);
  if (!configured) {
    return undefined;
  }

  for (const name of requiredTestVariables) {
    if (!environment[name]) {
      throw new Error(`Missing isolated test setting: ${name}`);
    }
  }

  const pgHost = environment.TEST_PGHOST!;
  const redisHost = environment.TEST_REDIS_HOST!;
  const database = environment.TEST_PGDATABASE!;
  const pgPort = Number(environment.TEST_PGPORT);
  const redisPort = Number(environment.TEST_REDIS_PORT);
  const redisDb = Number(environment.TEST_REDIS_DB);

  if (!['127.0.0.1', 'localhost', '::1'].includes(pgHost) || !database.endsWith('_test')) {
    throw new Error('Integration tests require a loopback host and a database ending in _test');
  }
  if (!['127.0.0.1', 'localhost', '::1'].includes(redisHost) || redisDb !== 15) {
    throw new Error('Integration tests require a loopback Redis host and dedicated DB index 15');
  }
  if (!Number.isInteger(pgPort) || pgPort < 1 || pgPort > 65_535) {
    throw new Error('Invalid isolated PostgreSQL test port');
  }
  if (!Number.isInteger(redisPort) || redisPort < 1 || redisPort > 65_535) {
    throw new Error('Invalid isolated Redis test port');
  }

  return {
    postgres: {
      host: pgHost,
      port: pgPort,
      database,
      user: environment.TEST_PGUSER!,
      password: environment.TEST_PGPASSWORD!,
      max: 3,
    },
    redis: {
      host: redisHost,
      port: redisPort,
      db: redisDb,
      ...(environment.TEST_REDIS_PASSWORD ? { password: environment.TEST_REDIS_PASSWORD } : {}),
    },
  };
}
