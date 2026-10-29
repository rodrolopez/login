import { Redis } from 'ioredis';

export interface RedisClientConfig {
  host: string;
  port: number;
  password?: string;
  db: number;
}

export function redisReconnectDelay(attempt: number): number {
  return Math.min(Math.max(1, attempt) * 200, 2_000);
}

export function createRedisClient(config: RedisClientConfig): Redis {
  const client = new Redis({
    host: config.host,
    port: config.port,
    ...(config.password ? { password: config.password } : {}),
    db: config.db,
    lazyConnect: true,
    enableOfflineQueue: false,
    maxRetriesPerRequest: 2,
    retryStrategy: redisReconnectDelay,
    connectionName: 'identity-api',
  });

  client.on('error', () => {
    process.stderr.write('[redis] connection error; retrying with capped backoff\n');
  });

  return client;
}
