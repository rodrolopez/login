import type { Response } from 'express';
import type { Redis } from 'ioredis';
import type { Pool } from 'pg';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiSessionService } from '../src/sessions/session.service.js';

describe('API session cookies', () => {
  afterEach(() => vi.unstubAllEnvs());

  it('uses HttpOnly and SameSite=Lax and enables Secure only in production', () => {
    const sessions = new ApiSessionService({} as Pool, {} as Redis);
    const developmentResponse = { append: vi.fn() } as unknown as Response;
    vi.stubEnv('NODE_ENV', 'development');
    sessions.setCookie(developmentResponse, 'opaque-development-session');

    const developmentCookie = vi.mocked(developmentResponse.append).mock.calls[0]?.[1];
    expect(developmentCookie).toContain('HttpOnly');
    expect(developmentCookie).toContain('SameSite=Lax');
    expect(developmentCookie).not.toContain('Secure');

    const productionResponse = { append: vi.fn() } as unknown as Response;
    vi.stubEnv('NODE_ENV', 'production');
    sessions.setCookie(productionResponse, 'opaque-production-session');

    const productionCookie = vi.mocked(productionResponse.append).mock.calls[0]?.[1];
    expect(productionCookie).toContain('HttpOnly');
    expect(productionCookie).toContain('SameSite=Lax');
    expect(productionCookie).toContain('Secure');
  });
});
