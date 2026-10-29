import { createHash, randomBytes } from 'node:crypto';
import type { Redis } from 'ioredis';

const CHALLENGE_TTL_SECONDS = 5 * 60;
const CHALLENGE_PREFIX = 'identity:mfa:login';
const CONSUME_CHALLENGE_SCRIPT = `
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
`;

export interface MfaLoginChallenge {
  userId: string;
  interactionUid?: string;
}

function challengeKey(rawToken: string): string {
  const digest = createHash('sha256').update(rawToken, 'utf8').digest('hex');
  return `${CHALLENGE_PREFIX}:${digest}`;
}

function isChallenge(value: unknown): value is MfaLoginChallenge {
  if (typeof value !== 'object' || value === null || !('userId' in value)) return false;
  if (typeof value.userId !== 'string') return false;
  return !('interactionUid' in value) || typeof value.interactionUid === 'string';
}

export class MfaLoginChallengeService {
  constructor(private readonly redis: Redis) {}

  async create(input: MfaLoginChallenge): Promise<string> {
    const token = randomBytes(32).toString('base64url');
    const result = await this.redis.set(
      challengeKey(token),
      JSON.stringify(input),
      'EX',
      CHALLENGE_TTL_SECONDS,
      'NX',
    );
    if (result !== 'OK') throw new Error('Unable to create MFA login challenge');
    return token;
  }

  async find(token: string): Promise<MfaLoginChallenge | undefined> {
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return undefined;
    const raw = await this.redis.get(challengeKey(token));
    if (!raw) return undefined;
    try {
      const parsed: unknown = JSON.parse(raw);
      return isChallenge(parsed) ? parsed : undefined;
    } catch {
      return undefined;
    }
  }

  async consume(token: string, challenge: MfaLoginChallenge): Promise<boolean> {
    const key = challengeKey(token);
    const expected = JSON.stringify(challenge);
    const result = await this.redis.eval(CONSUME_CHALLENGE_SCRIPT, 1, key, expected);
    return Number(result) === 1;
  }
}
