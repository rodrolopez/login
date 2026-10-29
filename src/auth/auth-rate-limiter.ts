import { createHmac } from 'node:crypto';
import type { Redis } from 'ioredis';

const CONSUME_ATTEMPT_SCRIPT = `
local pairCount = redis.call('INCR', KEYS[1])
if pairCount == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[3]) end
local ipCount = redis.call('INCR', KEYS[2])
if ipCount == 1 then redis.call('PEXPIRE', KEYS[2], ARGV[3]) end
if pairCount > tonumber(ARGV[1]) or ipCount > tonumber(ARGV[2]) then
  local pairTtl = redis.call('PTTL', KEYS[1])
  local ipTtl = redis.call('PTTL', KEYS[2])
  if pairTtl < ipTtl then pairTtl = ipTtl end
  return {0, pairTtl}
end
return {1, 0}
`;

export interface RateLimitDecision {
  allowed: boolean;
  retryAfterSeconds: number;
}

export class AuthAttemptRateLimiter {
  constructor(
    private readonly redis: Redis,
    private readonly keySecret: string,
    private readonly maxPerEmailAndIp = 5,
    private readonly maxPerIp = 60,
    private readonly windowMilliseconds = 15 * 60 * 1000,
    private readonly scope = 'login',
  ) {}

  async consume(ipAddress: string, normalizedEmail: string): Promise<RateLimitDecision> {
    const pairDigest = this.digest(`${normalizedEmail}\0${ipAddress}`);
    const ipDigest = this.digest(ipAddress);
    const result = (await this.redis.eval(
      CONSUME_ATTEMPT_SCRIPT,
      2,
      `identity-api:auth:${this.scope}:pair:${pairDigest}`,
      `identity-api:auth:${this.scope}:ip:${ipDigest}`,
      String(this.maxPerEmailAndIp),
      String(this.maxPerIp),
      String(this.windowMilliseconds),
    )) as [number | string, number | string];

    const allowed = Number(result[0]) === 1;
    const ttl = Number(result[1]);
    return {
      allowed,
      retryAfterSeconds: allowed ? 0 : Math.max(1, Math.ceil(ttl / 1000)),
    };
  }

  private digest(value: string): string {
    return createHmac('sha256', this.keySecret).update(value).digest('hex');
  }
}
