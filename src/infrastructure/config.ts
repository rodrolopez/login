import { z } from 'zod';

const postgresSchema = z.object({
  PGHOST: z.string().min(1).default('127.0.0.1'),
  PGPORT: z.coerce.number().int().min(1).max(65_535).default(5436),
  PGDATABASE: z.string().min(1),
  PGUSER: z.string().min(1),
  PGPASSWORD: z.string().min(1),
  PGPOOL_MAX: z.coerce.number().int().min(1).max(50).default(10),
});

const redisSchema = z.object({
  REDIS_HOST: z.string().min(1).default('127.0.0.1'),
  REDIS_PORT: z.coerce.number().int().min(1).max(65_535).default(6379),
  REDIS_PASSWORD: z.string().min(1),
  REDIS_DB: z.coerce.number().int().min(0).max(15).default(0),
});

export interface InfrastructureConfig {
  port: number;
  corsAllowedOrigins: string[];
  mfaEncryptionKey?: string;
  google?: { clientId: string; clientSecret: string; redirectUri: string };
  postgres: {
    host: string;
    port: number;
    database: string;
    user: string;
    password: string;
    max: number;
  };
  redis: {
    host: string;
    port: number;
    password: string;
    db: number;
  };
}

function readCorsOrigins(environment: NodeJS.ProcessEnv): string[] {
  const configured = environment.CORS_ALLOWED_ORIGINS?.trim() ?? '';
  if (!configured) return [];

  const origins = configured.split(',').map((value) => value.trim());
  if (origins.some((origin) => !origin)) throw new Error('Invalid CORS origin configuration');
  return origins.map((origin) => {
    let parsed: URL;
    try {
      parsed = new URL(origin);
    } catch {
      throw new Error('Invalid CORS origin configuration');
    }
    if (
      !['https:', 'http:'].includes(parsed.protocol) ||
      parsed.origin !== origin ||
      parsed.username ||
      parsed.password ||
      (environment.NODE_ENV === 'production' && parsed.protocol !== 'https:')
    ) {
      throw new Error('Invalid CORS origin configuration');
    }
    return parsed.origin;
  });
}

const googleSchema = z.object({
  GOOGLE_CLIENT_ID: z.string().min(1),
  GOOGLE_CLIENT_SECRET: z.string().min(1),
  GOOGLE_REDIRECT_URI: z.string().url(),
});

export function readGoogleConfig(
  environment: NodeJS.ProcessEnv = process.env,
): InfrastructureConfig['google'] {
  const names = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'GOOGLE_REDIRECT_URI'] as const;
  const configured = names.some(
    (name) => environment[name] !== undefined && environment[name] !== '',
  );
  if (!configured) return undefined;
  const result = googleSchema.safeParse(environment);
  if (!result.success) throw new Error('Invalid Google OAuth configuration');
  const redirect = new URL(result.data.GOOGLE_REDIRECT_URI);
  if (
    redirect.pathname !== '/auth/google/callback' ||
    redirect.search ||
    redirect.hash ||
    redirect.username ||
    redirect.password
  ) {
    throw new Error('Google OAuth redirect URI must target the configured callback route');
  }
  if (
    redirect.protocol !== 'https:' &&
    redirect.hostname !== '127.0.0.1' &&
    redirect.hostname !== 'localhost'
  ) {
    throw new Error('Google OAuth redirect URI must use HTTPS outside local development');
  }
  return {
    clientId: result.data.GOOGLE_CLIENT_ID,
    clientSecret: result.data.GOOGLE_CLIENT_SECRET,
    redirectUri: result.data.GOOGLE_REDIRECT_URI,
  };
}

export function readPostgresConfig(
  environment: NodeJS.ProcessEnv = process.env,
): InfrastructureConfig['postgres'] {
  const result = postgresSchema.safeParse(environment);

  if (!result.success) {
    throw new Error('Invalid PostgreSQL configuration');
  }

  const values = result.data;
  return {
    host: values.PGHOST,
    port: values.PGPORT,
    database: values.PGDATABASE,
    user: values.PGUSER,
    password: values.PGPASSWORD,
    max: values.PGPOOL_MAX,
  };
}

export function readRedisConfig(
  environment: NodeJS.ProcessEnv = process.env,
): InfrastructureConfig['redis'] {
  const result = redisSchema.safeParse(environment);
  if (!result.success) {
    throw new Error('Invalid Redis configuration');
  }

  const values = result.data;
  return {
    host: values.REDIS_HOST,
    port: values.REDIS_PORT,
    password: values.REDIS_PASSWORD,
    db: values.REDIS_DB,
  };
}

export function readInfrastructureConfig(
  environment: NodeJS.ProcessEnv = process.env,
): InfrastructureConfig {
  const portResult = z.coerce
    .number()
    .int()
    .min(1)
    .max(65_535)
    .default(3005)
    .safeParse(environment.PORT);
  if (!portResult.success) {
    throw new Error('Invalid API port configuration');
  }

  const google = readGoogleConfig(environment);
  const mfaEncryptionKey = environment.MFA_ENCRYPTION_KEY?.trim();
  if (mfaEncryptionKey && !/^[a-fA-F0-9]{64}$/.test(mfaEncryptionKey)) {
    throw new Error('Invalid MFA encryption key configuration');
  }
  return {
    port: portResult.data,
    corsAllowedOrigins: readCorsOrigins(environment),
    ...(mfaEncryptionKey ? { mfaEncryptionKey } : {}),
    ...(google ? { google } : {}),
    postgres: readPostgresConfig(environment),
    redis: readRedisConfig(environment),
  };
}
