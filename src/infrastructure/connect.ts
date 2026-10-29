import type { Pool } from 'pg';
import type { Redis } from 'ioredis';

const POSTGRES_MAX_ATTEMPTS = 5;
const REDIS_STARTUP_TIMEOUT_MS = 12_000;

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function verifyPostgres(pool: Pool): Promise<void> {
  for (let attempt = 1; attempt <= POSTGRES_MAX_ATTEMPTS; attempt += 1) {
    try {
      await pool.query('SELECT 1');
      return;
    } catch (error) {
      if (attempt === POSTGRES_MAX_ATTEMPTS) {
        throw error;
      }

      await delay(Math.min(attempt * 250, 1_000));
    }
  }
}

async function connectRedis(redis: Redis): Promise<void> {
  let timeout: NodeJS.Timeout | undefined;
  try {
    await Promise.race([
      redis.connect(),
      new Promise<never>((_, reject) => {
        timeout = setTimeout(
          () => reject(new Error('Redis startup connection timed out')),
          REDIS_STARTUP_TIMEOUT_MS,
        );
      }),
    ]);
  } finally {
    if (timeout) {
      clearTimeout(timeout);
    }
  }
}

export async function connectInfrastructure(pool: Pool, redis: Redis): Promise<void> {
  await Promise.all([verifyPostgres(pool), connectRedis(redis)]);
}
