import { Pool, type PoolClient } from 'pg';

export interface PostgresPoolConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  max: number;
}

export function createPostgresPool(config: PostgresPoolConfig): Pool {
  const pool = new Pool({
    ...config,
    application_name: 'identity-api',
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 30_000,
    keepAlive: true,
  });

  pool.on('error', () => {
    process.stderr.write('[postgres] idle connection error; the pool will replace it\n');
  });

  return pool;
}

export async function withTransaction<T>(
  pool: Pick<Pool, 'connect'>,
  operation: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  let discardClient = false;

  try {
    await client.query('BEGIN');
    const result = await operation(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {
      discardClient = true;
    }

    throw error;
  } finally {
    client.release(discardClient ? new Error('Transaction rollback failed') : undefined);
  }
}
