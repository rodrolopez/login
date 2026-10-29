import { createHash, randomBytes } from 'node:crypto';
import type { Request, Response } from 'express';
import type { Redis } from 'ioredis';
import type { Pool } from 'pg';
import { IdentityRepository } from '../identity/identity.repository.js';
import { revokeOidcArtifactsForAccount } from '../oidc/oidc-adapter.js';

export const API_SESSION_COOKIE = 'identity_session';
export const API_SESSION_TTL_SECONDS = 8 * 60 * 60;
const API_SESSION_KEY_PREFIX = 'identity:api-session';

function sessionDigest(raw: string): string {
  return createHash('sha256').update(raw).digest('hex');
}

function sessionKey(digest: string): string {
  return `${API_SESSION_KEY_PREFIX}:data:${digest}`;
}

function accountIndexKey(accountId: string): string {
  return `${API_SESSION_KEY_PREFIX}:account:${accountId}`;
}

function cookieSecure(): boolean {
  return process.env.NODE_ENV === 'production';
}

function cookieAttributes(): string {
  return `Path=/; HttpOnly; SameSite=Lax${cookieSecure() ? '; Secure' : ''}`;
}

function cookieValue(request: Request): string | undefined {
  const header = request.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0 || part.slice(0, separator).trim() !== API_SESSION_COOKIE) continue;
    try {
      return decodeURIComponent(part.slice(separator + 1).trim());
    } catch {
      return undefined;
    }
  }
  return undefined;
}

export class ApiSessionService {
  private readonly repository: IdentityRepository;

  constructor(
    private readonly pool: Pool,
    private readonly redis: Redis,
  ) {
    this.repository = new IdentityRepository(pool);
  }

  async create(accountId: string): Promise<string> {
    const token = randomBytes(32).toString('base64url');
    const digest = sessionDigest(token);
    const transaction = this.redis
      .multi()
      .set(sessionKey(digest), JSON.stringify({ accountId }), 'EX', API_SESSION_TTL_SECONDS)
      .sadd(accountIndexKey(accountId), digest)
      .expire(accountIndexKey(accountId), API_SESSION_TTL_SECONDS);
    const results = await transaction.exec();
    if (!results || results.some(([error]) => error)) {
      throw new Error('Unable to create API session');
    }
    return token;
  }

  async accountForRequest(request: Request): Promise<string | undefined> {
    const token = cookieValue(request);
    if (!token || token.length > 128) return undefined;
    const digest = sessionDigest(token);
    const key = sessionKey(digest);
    const raw = await this.redis.get(key);
    if (!raw) return undefined;

    try {
      const data: unknown = JSON.parse(raw);
      if (
        typeof data !== 'object' ||
        data === null ||
        !('accountId' in data) ||
        typeof data.accountId !== 'string'
      ) {
        throw new Error('Invalid API session payload');
      }
      const account = await this.repository.findAccountById(data.accountId);
      if (
        !account ||
        account.status !== 'active' ||
        !account.emails.some((email) => email.isPrimary && email.verifiedAt !== null)
      ) {
        await this.destroyByDigest(data.accountId, digest);
        return undefined;
      }
      return account.id;
    } catch (error) {
      if (error instanceof SyntaxError) {
        await this.redis.del(key);
        return undefined;
      }
      throw error;
    }
  }

  async destroyFromRequest(request: Request): Promise<void> {
    const token = cookieValue(request);
    if (!token || token.length > 128) return;
    const digest = sessionDigest(token);
    const raw = await this.redis.get(sessionKey(digest));
    if (!raw) {
      await this.redis.del(sessionKey(digest));
      return;
    }
    try {
      const data = JSON.parse(raw) as { accountId?: unknown };
      if (typeof data.accountId === 'string') {
        await this.destroyByDigest(data.accountId, digest);
        return;
      }
    } catch {
      // Deleting an unreadable session is safe and makes logout idempotent.
    }
    await this.redis.del(sessionKey(digest));
  }

  async revokeAccount(accountId: string): Promise<void> {
    const index = accountIndexKey(accountId);
    const digests = await this.redis.smembers(index);
    if (digests.length) {
      const transaction = this.redis
        .multi()
        .del(...digests.map(sessionKey))
        .del(index);
      const results = await transaction.exec();
      if (!results || results.some(([error]) => error)) {
        throw new Error('Unable to revoke API sessions');
      }
    } else {
      await this.redis.del(index);
    }
  }

  setCookie(response: Response, token: string): void {
    response.append(
      'Set-Cookie',
      `${API_SESSION_COOKIE}=${encodeURIComponent(token)}; ${cookieAttributes()}; Max-Age=${API_SESSION_TTL_SECONDS}`,
    );
  }

  clearCookie(response: Response): void {
    response.append(
      'Set-Cookie',
      `${API_SESSION_COOKIE}=; ${cookieAttributes()}; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
    );
  }

  private async destroyByDigest(accountId: string, digest: string): Promise<void> {
    const transaction = this.redis
      .multi()
      .del(sessionKey(digest))
      .srem(accountIndexKey(accountId), digest);
    const results = await transaction.exec();
    if (!results || results.some(([error]) => error)) {
      throw new Error('Unable to destroy API session');
    }
  }
}

export class IdentitySessionRevocationService {
  private readonly repository: IdentityRepository;
  private readonly sessions: ApiSessionService;

  constructor(
    private readonly pool: Pool,
    private readonly redis: Redis,
  ) {
    this.repository = new IdentityRepository(pool);
    this.sessions = new ApiSessionService(pool, redis);
  }

  async disableAccount(accountId: string): Promise<boolean> {
    const updated = await this.repository.disableAccount(accountId);
    if (updated) await this.revokeAccount(accountId);
    return updated;
  }

  async suspendAccount(accountId: string): Promise<boolean> {
    const updated = await this.repository.suspendAccount(accountId);
    if (updated) await this.revokeAccount(accountId);
    return updated;
  }

  async anonymizeAccount(accountId: string): Promise<boolean> {
    const updated = await this.repository.anonymizeAccount(accountId);
    if (updated) await this.revokeAccount(accountId);
    return updated;
  }

  async revokeAccountSessions(accountId: string): Promise<void> {
    await Promise.all([
      this.sessions.revokeAccount(accountId),
      revokeOidcArtifactsForAccount(this.pool, this.redis, accountId),
    ]);
  }

  private async revokeAccount(accountId: string): Promise<void> {
    await this.revokeAccountSessions(accountId);
  }
}
