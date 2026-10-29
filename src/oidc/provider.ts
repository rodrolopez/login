import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import Provider, { type ClientMetadata, type JWKS } from 'oidc-provider';
import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import { IdentityRepository } from '../identity/identity.repository.js';
import { createOidcAdapter } from './oidc-adapter.js';

export const PUBLIC_TEST_CLIENT_ID = 'identity-public-test-client';
export const CONFIDENTIAL_TEST_CLIENT_ID = 'identity-confidential-test-client';
export const BFF_REFERENCE_CLIENT_ID = 'bff-reference-client';
export const OIDC_MOUNT_PATH = '/oidc';

export interface OidcProviderOptions {
  pool: Pool;
  redis: Redis;
  issuer?: string;
  confidentialClientSecret?: string;
  cookieKeys?: string[];
  jwks?: JWKS;
  runtimeEnvironment?: string;
}

export interface OidcProviderSystem {
  provider: Provider;
  issuer: string;
  confidentialClientSecret: string;
  bffReferenceClientSecret: string;
}

function configuredClients(
  environment: NodeJS.ProcessEnv,
  production: boolean,
  secret: string,
  bffSecret: string,
): ClientMetadata[] {
  if (production) {
    if (!environment.OIDC_CLIENTS) throw new Error('OIDC clients must be configured in production');
    const parsed: unknown = JSON.parse(environment.OIDC_CLIENTS);
    if (!Array.isArray(parsed) || parsed.length === 0) {
      throw new Error('Invalid OIDC client configuration');
    }
    return parsed as ClientMetadata[];
  }

  return [
    {
      client_id: PUBLIC_TEST_CLIENT_ID,
      client_name: 'Identity API public development client',
      application_type: 'web',
      redirect_uris: ['http://127.0.0.1:4100/callback'],
      response_types: ['code'],
      grant_types: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_method: 'none',
      scope: 'openid email offline_access',
    },
    {
      client_id: CONFIDENTIAL_TEST_CLIENT_ID,
      client_name: 'Identity API confidential development client',
      application_type: 'web',
      client_secret: secret,
      redirect_uris: ['http://127.0.0.1:4200/callback'],
      response_types: ['code'],
      grant_types: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_method: 'client_secret_basic',
      scope: 'openid email offline_access',
    },
    {
      client_id: BFF_REFERENCE_CLIENT_ID,
      client_name: 'Identity API reference BFF client',
      application_type: 'web',
      client_secret: bffSecret,
      redirect_uris: ['http://127.0.0.1:4300/callback'],
      post_logout_redirect_uris: ['http://127.0.0.1:4300/logout/callback'],
      response_types: ['code'],
      grant_types: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_method: 'client_secret_basic',
      scope: 'openid email offline_access',
    },
  ];
}

function generateJwks(): JWKS {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const privateJwk = privateKey.export({ format: 'jwk' });
  return {
    keys: [
      {
        ...privateJwk,
        kid: randomUUID(),
        use: 'sig',
        alg: 'RS256',
      },
    ],
  };
}

function configuredJwks(environment: NodeJS.ProcessEnv, production: boolean): JWKS {
  const serialized = environment.OIDC_JWKS;
  if (serialized) {
    const parsed: unknown = JSON.parse(serialized);
    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      !('keys' in parsed) ||
      !Array.isArray(parsed.keys) ||
      parsed.keys.length === 0
    ) {
      throw new Error('Invalid OIDC signing key configuration');
    }
    return parsed as JWKS;
  }
  if (production) throw new Error('OIDC signing keys must be configured in production');
  return generateJwks();
}

export function createOidcProvider(options: OidcProviderOptions): OidcProviderSystem {
  const environment = process.env;
  const production = (options.runtimeEnvironment ?? environment.NODE_ENV) === 'production';
  if (production && !options.issuer && !environment.OIDC_ISSUER?.trim()) {
    throw new Error('OIDC issuer must be configured in production');
  }
  const issuer =
    options.issuer ?? (environment.OIDC_ISSUER?.trim() || 'http://127.0.0.1:3005/oidc');
  const confidentialClientSecret =
    options.confidentialClientSecret ??
    (environment.OIDC_CONFIDENTIAL_CLIENT_SECRET?.trim() ||
      (production ? '' : randomBytes(32).toString('base64url')));
  const bffReferenceClientSecret =
    environment.OIDC_BFF_CLIENT_SECRET?.trim() ||
    (production ? '' : randomBytes(32).toString('base64url'));
  const configuredCookieKeys = environment.OIDC_COOKIE_KEYS?.split(',')
    .map((key) => key.trim())
    .filter(Boolean);
  const cookieKeys =
    options.cookieKeys ??
    (configuredCookieKeys?.length
      ? configuredCookieKeys
      : production
        ? []
        : [randomBytes(32).toString('base64url')]);

  if (
    (!production && (!confidentialClientSecret || !bffReferenceClientSecret)) ||
    cookieKeys.length === 0
  ) {
    throw new Error('OIDC cookie and development client secrets must be configured');
  }
  if (cookieKeys.some((key) => Buffer.byteLength(key, 'utf8') < 32)) {
    throw new Error('OIDC cookie signing keys must contain at least 32 bytes');
  }
  if (
    [confidentialClientSecret, bffReferenceClientSecret].some(
      (key) => key && Buffer.byteLength(key, 'utf8') < 32,
    )
  ) {
    throw new Error('OIDC confidential client secrets must contain at least 32 bytes');
  }
  let issuerUrl: URL;
  try {
    issuerUrl = new URL(issuer);
  } catch {
    throw new Error('Invalid OIDC issuer URL');
  }
  if (
    !['http:', 'https:'].includes(issuerUrl.protocol) ||
    (production && issuerUrl.protocol !== 'https:')
  ) {
    throw new Error('OIDC issuer must use HTTPS in production');
  }

  const repository = new IdentityRepository(options.pool);
  const clients = configuredClients(
    environment,
    production,
    confidentialClientSecret,
    bffReferenceClientSecret,
  );
  const provider = new Provider(issuer, {
    adapter: createOidcAdapter(options.pool, options.redis),
    clients,
    clientBasedCORS: (context, origin, client) => {
      if (
        !origin ||
        origin === 'null' ||
        (context.oidc.route !== 'userinfo' && client.clientAuthMethod !== 'none')
      ) {
        return false;
      }
      let normalizedOrigin: string;
      try {
        const parsedOrigin = new URL(origin);
        if (
          !['https:', 'http:'].includes(parsedOrigin.protocol) ||
          parsedOrigin.origin !== origin
        ) {
          return false;
        }
        normalizedOrigin = parsedOrigin.origin;
      } catch {
        return false;
      }
      return (
        client.redirectUris?.some((redirectUri) => {
          try {
            const redirectOrigin = new URL(redirectUri).origin;
            return redirectOrigin !== 'null' && redirectOrigin === normalizedOrigin;
          } catch {
            return false;
          }
        }) ?? false
      );
    },
    cookies: {
      keys: cookieKeys,
      long: { path: '/', httpOnly: true, sameSite: 'lax', secure: production },
      short: { path: '/', httpOnly: true, sameSite: 'lax', secure: production },
    },
    jwks: options.jwks ?? configuredJwks(environment, production),
    claims: {
      openid: ['sub'],
      email: ['email', 'email_verified'],
    },
    scopes: ['openid', 'email', 'offline_access'],
    responseTypes: ['code'],
    ttl: {
      AccessToken: 10 * 60,
      IdToken: 10 * 60,
      Interaction: 10 * 60,
      Session: 8 * 60 * 60,
      Grant: 180 * 24 * 60 * 60,
      RefreshToken: 14 * 24 * 60 * 60,
    },
    issueRefreshToken: (_context, client, source) =>
      client.grantTypeAllowed('refresh_token') &&
      source.scope?.split(/\s+/).includes('offline_access') === true,
    rotateRefreshToken: true,
    expiresWithSession: () => true,
    features: {
      devInteractions: { enabled: false },
      registration: { enabled: false },
      registrationManagement: { enabled: false },
      pushedAuthorizationRequests: { enabled: false },
      rpInitiatedLogout: {
        enabled: true,
        logoutSource: (context, form) => {
          context.type = 'html';
          context.set(
            'Content-Security-Policy',
            "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
          );
          context.body = `<!doctype html><html lang="en"><meta charset="utf-8"><title>Sign out</title><body><h1>Sign out</h1>${form}<button type="submit" form="op.logoutForm">Confirm sign out</button></body></html>`;
        },
        postLogoutSuccessSource: (context) => {
          context.type = 'html';
          context.body =
            '<!doctype html><html lang="en"><meta charset="utf-8"><title>Signed out</title><body><p>You have been signed out.</p></body></html>';
        },
      },
    },
    pkce: { required: () => true },
    interactions: {
      url: (_context, interaction) => `${OIDC_MOUNT_PATH}/interaction/${interaction.uid}`,
    },
    findAccount: async (_context, accountId) => {
      const account = await repository.findAccountById(accountId);
      if (
        !account ||
        account.status !== 'active' ||
        !account.emails.some((email) => email.isPrimary && email.verifiedAt !== null)
      ) {
        return undefined;
      }
      const email = account.emails.find((candidate) => candidate.isPrimary);
      return {
        accountId,
        claims: async (_use, scope) => {
          const claims: { sub: string; email?: string; email_verified?: boolean } = {
            sub: accountId,
          };
          if (scope.split(/\s+/).includes('email') && email) {
            claims.email = email.email;
            claims.email_verified = email.verifiedAt !== null;
          }
          return claims;
        },
      };
    },
  });
  provider.proxy = production;

  return { provider, issuer, confidentialClientSecret, bffReferenceClientSecret };
}

export function createOidcProviderFromEnvironment(pool: Pool, redis: Redis): OidcProviderSystem {
  const production = process.env.NODE_ENV === 'production';
  return createOidcProvider({
    pool,
    redis,
    runtimeEnvironment: production ? 'production' : 'development',
  });
}
