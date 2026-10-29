import type { RequestHandler } from 'express';
import { messages, requestLanguage } from '../auth/i18n.js';

const ALLOWED_METHODS = new Set(['GET', 'POST', 'PATCH']);
const ALLOWED_HEADERS = new Set(['accept-language', 'authorization', 'content-type']);

export const securityHeaders: RequestHandler = (_request, response, next) => {
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('X-Frame-Options', 'DENY');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  response.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'",
  );
  if (process.env.NODE_ENV === 'production') {
    response.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
};

function isOidcRequest(path: string): boolean {
  return path === '/oidc' || path.startsWith('/oidc/');
}

function isValidOrigin(origin: string): boolean {
  if (origin === 'null') return false;
  try {
    const parsed = new URL(origin);
    return ['http:', 'https:'].includes(parsed.protocol) && parsed.origin === origin;
  } catch {
    return false;
  }
}

function isSameOrigin(requestOrigin: string, requestProtocol: string, host: string): boolean {
  try {
    return new URL(requestOrigin).origin === new URL(`${requestProtocol}://${host}`).origin;
  } catch {
    return false;
  }
}

export function createCorsMiddleware(allowedOrigins: string[]): RequestHandler {
  const allowlist = new Set(allowedOrigins);

  return (request, response, next) => {
    const origin = request.get('Origin');
    if (!origin || isOidcRequest(request.path)) return next();

    response.vary('Origin');
    const host = request.get('host') ?? '';
    const allowed =
      isValidOrigin(origin) &&
      (allowlist.has(origin) || isSameOrigin(origin, request.protocol, host));
    if (!allowed) {
      const language = requestLanguage(response);
      return response.status(403).json({ error: messages[language].crossOriginDenied });
    }

    response.setHeader('Access-Control-Allow-Origin', origin);
    response.setHeader('Access-Control-Allow-Credentials', 'true');
    response.setHeader('Access-Control-Allow-Methods', [...ALLOWED_METHODS, 'OPTIONS'].join(','));
    response.setHeader('Access-Control-Allow-Headers', [...ALLOWED_HEADERS].join(','));
    response.setHeader('Access-Control-Max-Age', '600');

    if (request.method === 'OPTIONS') {
      const requestedMethod = request.get('Access-Control-Request-Method')?.toUpperCase();
      const requestedHeaders = (request.get('Access-Control-Request-Headers') ?? '')
        .split(',')
        .map((header) => header.trim().toLowerCase())
        .filter(Boolean);
      if (
        !requestedMethod ||
        !ALLOWED_METHODS.has(requestedMethod) ||
        requestedHeaders.some((header) => !ALLOWED_HEADERS.has(header))
      ) {
        const language = requestLanguage(response);
        return response.status(403).json({ error: messages[language].crossOriginDenied });
      }
      return response.status(204).end();
    }

    return next();
  };
}
