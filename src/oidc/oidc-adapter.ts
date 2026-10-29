import type { Adapter, AdapterPayload } from 'oidc-provider';
import type { Redis } from 'ioredis';
import type { Pool } from 'pg';

const DEFAULT_TTL_SECONDS = 60 * 60 * 24 * 14;

function encoded(value: string): string {
  return Buffer.from(value).toString('base64url');
}

function payloadIndexes(payload: AdapterPayload): string[] {
  const indexes: string[] = [];
  if (payload.accountId) indexes.push(`accountId:${encoded(payload.accountId)}`);
  if (payload.uid) indexes.push(`uid:${encoded(payload.uid)}`);
  if (payload.userCode) indexes.push(`userCode:${encoded(payload.userCode)}`);
  if (payload.grantId) indexes.push(`grantId:${encoded(payload.grantId)}`);
  return indexes;
}

const OIDC_REDIS_MODEL_NAMES = [
  'AccessToken',
  'AuthorizationCode',
  'BackchannelAuthenticationRequest',
  'DeviceCode',
  'IdToken',
  'Interaction',
  'PushedAuthorizationRequest',
  'RefreshToken',
  'Session',
] as const;

export async function revokeOidcArtifactsForAccount(
  pool: Pool,
  redis: Redis,
  accountId: string,
): Promise<void> {
  const accountIndex = `accountId:${encoded(accountId)}`;
  for (const model of OIDC_REDIS_MODEL_NAMES) {
    const prefix = `identity:oidc:${model}`;
    const indexKey = `${prefix}:index:${accountIndex}`;
    const dataKeys = await redis.smembers(indexKey);
    for (const dataKey of dataKeys) {
      const raw = await redis.get(dataKey);
      const transaction = redis.multi().del(dataKey).srem(indexKey, dataKey);
      if (raw) {
        try {
          const payload = JSON.parse(raw) as AdapterPayload;
          for (const index of payloadIndexes(payload)) {
            transaction.srem(`${prefix}:index:${index}`, dataKey);
          }
        } catch {
          // The data key and account index entry are removed even if the payload is corrupt.
        }
      }
      const results = await transaction.exec();
      if (!results || results.some(([error]) => error)) {
        throw new Error('Unable to revoke OIDC session artifacts');
      }
    }
    await redis.del(indexKey);
  }

  await pool.query('DELETE FROM identity_api.oidc_grants WHERE account_id = $1', [accountId]);
}

export function createOidcAdapter(pool: Pool, redis: Redis) {
  return class OidcAdapter implements Adapter {
    constructor(private readonly name: string) {}

    private get prefix(): string {
      return `identity:oidc:${this.name}`;
    }

    private dataKey(id: string): string {
      return `${this.prefix}:data:${encoded(id)}`;
    }

    private indexKey(index: string): string {
      return `${this.prefix}:index:${index}`;
    }

    private async execute(transaction: ReturnType<Redis['multi']>): Promise<void> {
      const results = await transaction.exec();
      if (!results) throw new Error('OIDC Redis adapter transaction failed');
      for (const [error] of results) {
        if (error) throw new Error('OIDC Redis adapter transaction failed');
      }
    }

    private async readRedis(id: string): Promise<AdapterPayload | undefined> {
      const raw = await redis.get(this.dataKey(id));
      if (!raw) return undefined;
      try {
        return JSON.parse(raw) as AdapterPayload;
      } catch {
        await redis.del(this.dataKey(id));
        return undefined;
      }
    }

    async upsert(id: string, payload: AdapterPayload, expiresIn?: number): Promise<void> {
      if (this.name === 'Grant') {
        if (!payload.accountId || !payload.clientId) {
          throw new Error('OIDC grant is missing its account or client binding');
        }
        const expiration =
          expiresIn && expiresIn > 0 ? new Date(Date.now() + expiresIn * 1000) : null;
        await pool.query(
          `INSERT INTO identity_api.oidc_grants (grant_id, account_id, client_id, payload, expires_at)
           VALUES ($1, $2, $3, $4::jsonb, $5)
           ON CONFLICT (grant_id) DO UPDATE SET
             account_id = EXCLUDED.account_id,
             client_id = EXCLUDED.client_id,
             payload = EXCLUDED.payload,
             expires_at = EXCLUDED.expires_at,
             updated_at = now()`,
          [id, payload.accountId, payload.clientId, JSON.stringify(payload), expiration],
        );
        return;
      }

      const previous = await this.readRedis(id);
      const ttl = Math.max(1, Math.floor(expiresIn ?? DEFAULT_TTL_SECONDS));
      const transaction = redis.multi();
      if (previous) {
        for (const index of payloadIndexes(previous)) {
          transaction.srem(this.indexKey(index), this.dataKey(id));
        }
      }
      transaction.set(this.dataKey(id), JSON.stringify(payload), 'EX', ttl);
      for (const index of payloadIndexes(payload)) {
        transaction.sadd(this.indexKey(index), this.dataKey(id));
      }
      await this.execute(transaction);
      for (const index of payloadIndexes(payload)) {
        await redis.eval(
          `redis.call('SADD', KEYS[1], ARGV[1])
           local current = redis.call('TTL', KEYS[1])
           local requested = tonumber(ARGV[2])
           if current < requested then redis.call('EXPIRE', KEYS[1], requested) end
           return 1`,
          1,
          this.indexKey(index),
          this.dataKey(id),
          String(ttl),
        );
      }
    }

    async find(id: string): Promise<AdapterPayload | undefined> {
      if (this.name === 'Grant') {
        const result = await pool.query<{ payload: AdapterPayload }>(
          `SELECT payload FROM identity_api.oidc_grants
           WHERE grant_id = $1 AND (expires_at IS NULL OR expires_at > now())`,
          [id],
        );
        return result.rows[0]?.payload;
      }
      return this.readRedis(id);
    }

    async findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
      const dataKeys = await redis.smembers(this.indexKey(`userCode:${encoded(userCode)}`));
      for (const dataKey of dataKeys) {
        const raw = await redis.get(dataKey);
        if (raw) {
          try {
            return JSON.parse(raw) as AdapterPayload;
          } catch {
            await redis.srem(this.indexKey(`userCode:${encoded(userCode)}`), dataKey);
          }
        } else {
          await redis.srem(this.indexKey(`userCode:${encoded(userCode)}`), dataKey);
        }
      }
      return undefined;
    }

    async findByUid(uid: string): Promise<AdapterPayload | undefined> {
      const dataKeys = await redis.smembers(this.indexKey(`uid:${encoded(uid)}`));
      for (const dataKey of dataKeys) {
        const raw = await redis.get(dataKey);
        if (raw) {
          try {
            return JSON.parse(raw) as AdapterPayload;
          } catch {
            await redis.srem(this.indexKey(`uid:${encoded(uid)}`), dataKey);
          }
        } else {
          await redis.srem(this.indexKey(`uid:${encoded(uid)}`), dataKey);
        }
      }
      return undefined;
    }

    async consume(id: string): Promise<void> {
      if (this.name === 'Grant') return;
      await redis.eval(
        `local raw = redis.call('GET', KEYS[1])
         if not raw then return 0 end
         local payload = cjson.decode(raw)
         if payload.consumed then return 0 end
         local ttl = redis.call('TTL', KEYS[1])
         if ttl < 1 then return 0 end
         payload.consumed = tonumber(ARGV[1])
         redis.call('SET', KEYS[1], cjson.encode(payload), 'EX', ttl)
         return 1`,
        1,
        this.dataKey(id),
        String(Math.floor(Date.now() / 1000)),
      );
    }

    async destroy(id: string): Promise<void> {
      if (this.name === 'Grant') {
        await pool.query('DELETE FROM identity_api.oidc_grants WHERE grant_id = $1', [id]);
        return;
      }
      const payload = await this.readRedis(id);
      const transaction = redis.multi().del(this.dataKey(id));
      if (payload) {
        for (const index of payloadIndexes(payload)) {
          transaction.srem(this.indexKey(index), this.dataKey(id));
        }
      }
      await this.execute(transaction);
    }

    async revokeByGrantId(grantId: string): Promise<void> {
      if (this.name === 'Grant') return;
      const index = this.indexKey(`grantId:${encoded(grantId)}`);
      const dataKeys = await redis.smembers(index);
      for (const dataKey of dataKeys) {
        const raw = await redis.get(dataKey);
        if (!raw) {
          await redis.srem(index, dataKey);
          continue;
        }
        try {
          const payload = JSON.parse(raw) as AdapterPayload;
          const transaction = redis.multi().del(dataKey).srem(index, dataKey);
          for (const item of payloadIndexes(payload)) {
            if (item !== `grantId:${encoded(grantId)}`) {
              transaction.srem(this.indexKey(item), dataKey);
            }
          }
          await this.execute(transaction);
        } catch {
          await redis.del(dataKey);
          await redis.srem(index, dataKey);
        }
      }
    }
  };
}
