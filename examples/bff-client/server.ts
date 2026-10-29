import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import 'dotenv/config';
import express, { type Request, type Response } from 'express';
import * as oidc from 'openid-client';

const DEFAULT_ISSUER = 'http://127.0.0.1:3005/oidc';
const DEFAULT_IDENTITY_BASE_URL = 'http://127.0.0.1:3005';
const DEFAULT_BFF_BASE_URL = 'http://127.0.0.1:4300';
const CLIENT_ID = 'bff-reference-client';
const BFF_SESSION_COOKIE = 'bff_session';
const LOGIN_STATE_COOKIE = 'bff_login_state';
const FLOW_TTL_MS = 5 * 60 * 1000;
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const MAX_REDIRECT_HOPS = 6;

interface BffOptions {
  issuer?: string;
  identityBaseUrl?: string;
  baseUrl?: string;
  clientSecret?: string;
  fetchImplementation?: typeof fetch;
}

interface LoginFlow {
  state: string;
  nonce: string;
  verifier: string;
  interactionUid: string;
  identityCookies: Map<string, string>;
  createdAt: number;
  mfaChallengeId?: string;
  consentUid?: string;
}

interface LocalSession {
  subject: string;
  accessToken: string;
  idToken: string;
  refreshToken?: string;
  accessTokenExpiresAt: number;
  csrfToken: string;
  expiresAt: number;
}

interface Runtime {
  app: express.Express;
  close(): void;
}

function digest(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => {
    const entities: Record<string, string> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
    };
    return entities[character] ?? character;
  });
}

function readCookie(request: Request, name: string): string | undefined {
  for (const item of (request.headers.cookie ?? '').split(';')) {
    const separator = item.indexOf('=');
    if (separator < 0 || item.slice(0, separator).trim() !== name) continue;
    try {
      return decodeURIComponent(item.slice(separator + 1).trim());
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function constantTimeEqual(left: string | undefined, right: string): boolean {
  if (!left) return false;
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function cookieAttributes(baseUrl: URL): string {
  return `Path=/; HttpOnly; SameSite=Lax${baseUrl.protocol === 'https:' ? '; Secure' : ''}`;
}

function clearCookie(response: Response, name: string, baseUrl: URL): void {
  response.append(
    'Set-Cookie',
    `${name}=; ${cookieAttributes(baseUrl)}; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
  );
}

function loginForm(state: string, message = ''): string {
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Sign in</title><body><main><h1>Sign in to Identity API</h1>${message ? `<p role="alert">${escapeHtml(message)}</p>` : ''}<form method="post" action="/login"><input type="hidden" name="state" value="${escapeHtml(state)}"><label>Email <input type="email" name="email" autocomplete="username" required maxlength="320"></label><label>Password <input type="password" name="password" autocomplete="current-password" required maxlength="128"></label><button type="submit">Continue</button></form></main></body></html>`;
}

function mfaForm(state: string, challengeId: string, message = ''): string {
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Verify sign in</title><body><main><h1>Additional verification</h1>${message ? `<p role="alert">${escapeHtml(message)}</p>` : ''}<form method="post" action="/mfa"><input type="hidden" name="state" value="${escapeHtml(state)}"><input type="hidden" name="challengeId" value="${escapeHtml(challengeId)}"><label>Authenticator code or recovery code <input name="factor" autocomplete="one-time-code" required maxlength="35"></label><button type="submit">Verify</button></form></main></body></html>`;
}

function consentForm(state: string, uid: string, scope: string): string {
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Consent</title><body><main><h1>Authorize reference BFF</h1><p>Requested scopes: ${escapeHtml(scope)}</p><form method="post" action="/consent"><input type="hidden" name="state" value="${escapeHtml(state)}"><input type="hidden" name="uid" value="${escapeHtml(uid)}"><button type="submit">Approve</button></form></main></body></html>`;
}

function identityCookies(flow: LoginFlow): string | undefined {
  if (flow.identityCookies.size === 0) return undefined;
  return [...flow.identityCookies.entries()].map(([name, value]) => `${name}=${value}`).join('; ');
}

function updateIdentityCookies(flow: LoginFlow, response: globalThis.Response): void {
  for (const cookie of response.headers.getSetCookie()) {
    const pair = cookie.split(';', 1)[0];
    const separator = pair?.indexOf('=') ?? -1;
    if (separator <= 0 || !pair) continue;
    const name = pair.slice(0, separator);
    const value = pair.slice(separator + 1);
    if (/;\s*max-age=0/i.test(cookie) || /expires=thu, 01 jan 1970/i.test(cookie)) {
      flow.identityCookies.delete(name);
    } else {
      flow.identityCookies.set(name, value);
    }
  }
}

export async function createBffRuntime(options: BffOptions = {}): Promise<Runtime> {
  const issuer = new URL(options.issuer ?? (process.env.OIDC_ISSUER?.trim() || DEFAULT_ISSUER));
  const identityBaseUrl = new URL(options.identityBaseUrl ?? DEFAULT_IDENTITY_BASE_URL);
  const baseUrl = new URL(
    options.baseUrl ?? (process.env.BFF_BASE_URL?.trim() || DEFAULT_BFF_BASE_URL),
  );
  const clientSecret = options.clientSecret ?? process.env.OIDC_BFF_CLIENT_SECRET;
  if (!clientSecret || Buffer.byteLength(clientSecret, 'utf8') < 32) {
    throw new Error('OIDC_BFF_CLIENT_SECRET must contain at least 32 bytes');
  }
  if (issuer.origin !== identityBaseUrl.origin) {
    throw new Error('OIDC issuer and identity API must share an origin in this local example');
  }
  const loopbackHosts = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);
  if (
    issuer.protocol === 'http:' &&
    (!loopbackHosts.has(issuer.hostname) || !loopbackHosts.has(identityBaseUrl.hostname))
  ) {
    throw new Error('The BFF example only permits HTTP for loopback development hosts');
  }
  if (!loopbackHosts.has(baseUrl.hostname)) {
    throw new Error('The reference BFF only binds to a loopback browser origin');
  }
  const callbackUri = new URL('/callback', baseUrl).href;
  const logoutCallbackUri = new URL('/logout/callback', baseUrl).href;
  const configuration = await oidc.discovery(
    issuer,
    CLIENT_ID,
    { redirect_uris: [callbackUri], response_types: ['code'] },
    oidc.ClientSecretBasic(clientSecret),
    issuer.protocol === 'http:' ? { execute: [oidc.allowInsecureRequests] } : {},
  );

  const app = express();
  const fetchImplementation = options.fetchImplementation ?? fetch;
  const flows = new Map<string, LoginFlow>();
  const sessions = new Map<string, LocalSession>();
  const logoutStates = new Map<string, number>();
  const baseCookieAttributes = cookieAttributes(baseUrl);
  const identityHost = issuer.host;

  app.disable('x-powered-by');
  app.use((request, response, next) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('X-Frame-Options', 'DENY');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'",
    );
    next();
  });
  app.use(express.urlencoded({ extended: false, limit: '8kb' }));

  const getFlow = (state: string | undefined): LoginFlow | undefined => {
    if (!state) return undefined;
    const flow = flows.get(state);
    if (!flow || Date.now() - flow.createdAt > FLOW_TTL_MS) {
      flows.delete(state);
      return undefined;
    }
    return flow;
  };

  const getSession = (request: Request): { key: string; session: LocalSession } | undefined => {
    const raw = readCookie(request, BFF_SESSION_COOKIE);
    if (!raw || raw.length > 128) return undefined;
    const key = digest(raw);
    const session = sessions.get(key);
    if (!session || session.expiresAt <= Date.now()) {
      sessions.delete(key);
      return undefined;
    }
    return { key, session };
  };

  const callIdentity = async (
    url: URL,
    flow: LoginFlow,
    init: RequestInit = {},
  ): Promise<globalThis.Response> => {
    const headers = new Headers(init.headers);
    headers.set('Host', identityHost);
    if (identityCookies(flow)) headers.set('Cookie', identityCookies(flow)!);
    const result = await fetchImplementation(url, { ...init, headers, redirect: 'manual' });
    updateIdentityCookies(flow, result);
    return result;
  };

  const responseLocation = (result: globalThis.Response, current: URL): URL | undefined => {
    const location = result.headers.get('location');
    if (!location) return undefined;
    try {
      return new URL(location, current);
    } catch {
      return undefined;
    }
  };

  const renderConsent = async (
    flow: LoginFlow,
    interactionUrl: URL,
    response: Response,
  ): Promise<void> => {
    const interaction = await callIdentity(interactionUrl, flow);
    if (!interaction.ok) throw new Error('Consent interaction unavailable');
    const details = (await interaction.json()) as {
      interactionUid?: unknown;
      prompt?: unknown;
      requestedScopes?: unknown;
    };
    if (
      details.prompt !== 'consent' ||
      typeof details.interactionUid !== 'string' ||
      details.interactionUid !== interactionUrl.pathname.split('/').at(-1) ||
      typeof details.requestedScopes !== 'string'
    ) {
      throw new Error('Unexpected OIDC interaction');
    }
    const consentUid = details.interactionUid;
    flow.consentUid = consentUid;
    response
      .status(200)
      .type('html')
      .send(consentForm(flow.state, consentUid, details.requestedScopes));
  };

  const completeCallback = async (
    flow: LoginFlow,
    callbackUrl: URL,
    response: Response,
  ): Promise<void> => {
    const tokens = await oidc.authorizationCodeGrant(configuration, callbackUrl, {
      pkceCodeVerifier: flow.verifier,
      expectedState: flow.state,
      expectedNonce: flow.nonce,
    });
    const claims = tokens.claims();
    if (!tokens.access_token || !tokens.id_token || !claims || typeof claims.sub !== 'string') {
      throw new Error('OIDC token response was incomplete');
    }
    const sessionId = randomBytes(32).toString('base64url');
    const session: LocalSession = {
      subject: claims.sub,
      accessToken: tokens.access_token,
      idToken: tokens.id_token,
      ...(tokens.refresh_token ? { refreshToken: tokens.refresh_token } : {}),
      accessTokenExpiresAt: Date.now() + Number(tokens.expires_in ?? 600) * 1000,
      csrfToken: randomBytes(32).toString('base64url'),
      expiresAt: Date.now() + SESSION_TTL_MS,
    };
    sessions.set(digest(sessionId), session);
    flows.delete(flow.state);
    response.append(
      'Set-Cookie',
      `${BFF_SESSION_COOKIE}=${encodeURIComponent(sessionId)}; ${baseCookieAttributes}; Max-Age=${SESSION_TTL_MS / 1000}`,
    );
    for (const [name, value] of flow.identityCookies) {
      response.append(
        'Set-Cookie',
        `${name}=${value}; Path=/; HttpOnly; SameSite=Lax${issuer.protocol === 'https:' ? '; Secure' : ''}`,
      );
    }
    clearCookie(response, LOGIN_STATE_COOKIE, baseUrl);
    response.redirect(303, '/protected');
  };

  const resumeAuthorization = async (
    flow: LoginFlow,
    initialLocation: URL,
    response: Response,
  ): Promise<void> => {
    let current = initialLocation;
    for (let hop = 0; hop < MAX_REDIRECT_HOPS; hop += 1) {
      if (current.origin === baseUrl.origin && current.pathname === '/callback') {
        if (current.searchParams.get('state') !== flow.state || current.searchParams.has('error')) {
          throw new Error('OIDC callback state did not match');
        }
        await completeCallback(flow, current, response);
        return;
      }
      if (current.origin !== issuer.origin)
        throw new Error('OIDC redirect left the configured issuer');
      const result = await callIdentity(current, flow);
      const nextLocation = responseLocation(result, current);
      if (nextLocation) {
        current = nextLocation;
        continue;
      }
      if (result.ok && current.pathname.startsWith(`${issuer.pathname}/interaction/`)) {
        await renderConsent(flow, current, response);
        return;
      }
      throw new Error('OIDC authorization did not continue as expected');
    }
    throw new Error('OIDC authorization exceeded redirect limit');
  };

  app.get('/', (_request, response) => {
    const activeSession = getSession(_request);
    if (!activeSession) {
      return response
        .type('html')
        .send(
          '<!doctype html><html lang="en"><meta charset="utf-8"><title>Reference BFF</title><body><h1>Reference BFF</h1><a href="/login">Sign in</a></body></html>',
        );
    }
    return response
      .type('html')
      .send(
        `<!doctype html><html lang="en"><meta charset="utf-8"><title>Reference BFF</title><body><h1>Reference BFF</h1><p>Signed in as ${escapeHtml(activeSession.session.subject)}</p><a href="/protected">Protected resource</a><form method="post" action="/logout"><input type="hidden" name="csrf" value="${escapeHtml(activeSession.session.csrfToken)}"><button type="submit">Sign out</button></form></body></html>`,
      );
  });

  app.get('/login', async (_request, response) => {
    const state = oidc.randomState();
    const nonce = oidc.randomNonce();
    const verifier = oidc.randomPKCECodeVerifier();
    const challenge = await oidc.calculatePKCECodeChallenge(verifier);
    const flow: LoginFlow = {
      state,
      nonce,
      verifier,
      interactionUid: '',
      identityCookies: new Map(),
      createdAt: Date.now(),
    };
    const authorizationUrl = oidc.buildAuthorizationUrl(configuration, {
      redirect_uri: callbackUri,
      response_type: 'code',
      scope: 'openid email offline_access',
      state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      prompt: 'consent',
    });
    const authorization = await callIdentity(authorizationUrl, flow);
    const interactionUrl = responseLocation(authorization, authorizationUrl);
    if (!interactionUrl || interactionUrl.origin !== issuer.origin) {
      return response
        .status(503)
        .type('html')
        .send(loginForm(state, 'Identity service is unavailable.'));
    }
    const interaction = await callIdentity(interactionUrl, flow);
    if (!interaction.ok) {
      return response
        .status(503)
        .type('html')
        .send(loginForm(state, 'Identity service is unavailable.'));
    }
    const prompt = (await interaction.json()) as { interactionUid?: unknown; prompt?: unknown };
    if (prompt.prompt !== 'login' || typeof prompt.interactionUid !== 'string') {
      return response.status(400).type('html').send(loginForm(state, 'Unable to start sign in.'));
    }
    flow.interactionUid = prompt.interactionUid;
    flows.set(state, flow);
    response.append(
      'Set-Cookie',
      `${LOGIN_STATE_COOKIE}=${encodeURIComponent(state)}; ${baseCookieAttributes}; Max-Age=${FLOW_TTL_MS / 1000}`,
    );
    return response.type('html').send(loginForm(state));
  });

  app.post('/login', async (request, response) => {
    const state = typeof request.body.state === 'string' ? request.body.state : undefined;
    const flow = getFlow(state);
    if (!flow || !constantTimeEqual(readCookie(request, LOGIN_STATE_COOKIE), flow.state)) {
      clearCookie(response, LOGIN_STATE_COOKIE, baseUrl);
      return response
        .status(400)
        .type('html')
        .send(
          '<!doctype html><html><title>Sign in failed</title><body><p>Sign-in request expired. Start again.</p><a href="/login">Try again</a></body></html>',
        );
    }
    const email = typeof request.body.email === 'string' ? request.body.email : '';
    const password = typeof request.body.password === 'string' ? request.body.password : '';
    if (!email || !password || email.length > 320 || password.length > 128) {
      return response
        .status(400)
        .type('html')
        .send(loginForm(flow.state, 'Enter a valid email and password.'));
    }
    const result = await callIdentity(new URL('/auth/login', identityBaseUrl), flow, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, interactionUid: flow.interactionUid }),
    });
    if (result.status === 202) {
      const challenge = (await result.json()) as { challengeId?: unknown; mfaRequired?: unknown };
      if (challenge.mfaRequired === true && typeof challenge.challengeId === 'string') {
        flow.mfaChallengeId = challenge.challengeId;
        return response.type('html').send(mfaForm(flow.state, challenge.challengeId));
      }
    }
    const location = responseLocation(result, new URL('/auth/login', identityBaseUrl));
    if (location && (result.status === 302 || result.status === 303)) {
      await resumeAuthorization(flow, location, response);
      return;
    }
    return response
      .status(401)
      .type('html')
      .send(loginForm(flow.state, 'Credentials could not be verified.'));
  });

  app.post('/mfa', async (request, response) => {
    const state = typeof request.body.state === 'string' ? request.body.state : undefined;
    const flow = getFlow(state);
    if (
      !flow ||
      !flow.mfaChallengeId ||
      !constantTimeEqual(readCookie(request, LOGIN_STATE_COOKIE), flow.state)
    ) {
      return response
        .status(400)
        .type('html')
        .send(
          '<!doctype html><html><title>Verification failed</title><body><p>Sign-in request expired. Start again.</p><a href="/login">Try again</a></body></html>',
        );
    }
    const factor = typeof request.body.factor === 'string' ? request.body.factor.trim() : '';
    const payload = /^[0-9]{6}$/.test(factor)
      ? { challengeId: flow.mfaChallengeId, token: factor }
      : { challengeId: flow.mfaChallengeId, recoveryCode: factor };
    const result = await callIdentity(new URL('/auth/mfa/totp/verify', identityBaseUrl), flow, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const location = responseLocation(result, new URL('/auth/mfa/totp/verify', identityBaseUrl));
    if (location && (result.status === 302 || result.status === 303)) {
      await resumeAuthorization(flow, location, response);
      return;
    }
    return response
      .status(401)
      .type('html')
      .send(mfaForm(flow.state, flow.mfaChallengeId, 'The verification code was invalid.'));
  });

  app.post('/consent', async (request, response) => {
    const state = typeof request.body.state === 'string' ? request.body.state : undefined;
    const uid = typeof request.body.uid === 'string' ? request.body.uid : undefined;
    const flow = getFlow(state);
    if (
      !flow ||
      !flow.consentUid ||
      uid !== flow.consentUid ||
      !constantTimeEqual(readCookie(request, LOGIN_STATE_COOKIE), flow.state)
    ) {
      return response
        .status(400)
        .type('html')
        .send(
          '<!doctype html><html><title>Consent failed</title><body><p>Consent request expired. Start again.</p><a href="/login">Try again</a></body></html>',
        );
    }
    const result = await callIdentity(
      new URL(`/oidc/interaction/${encodeURIComponent(uid)}/consent`, identityBaseUrl),
      flow,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approve: true }),
      },
    );
    const location = responseLocation(
      result,
      new URL(`/oidc/interaction/${encodeURIComponent(uid)}/consent`, identityBaseUrl),
    );
    if (!location || (result.status !== 302 && result.status !== 303)) {
      return response
        .status(400)
        .type('html')
        .send(
          '<!doctype html><html><title>Consent failed</title><body><p>Consent could not be completed.</p></body></html>',
        );
    }
    delete flow.consentUid;
    return await resumeAuthorization(flow, location, response);
  });

  app.get('/callback', async (request, response) => {
    const state = typeof request.query.state === 'string' ? request.query.state : undefined;
    const flow = getFlow(state);
    if (!flow || !constantTimeEqual(readCookie(request, LOGIN_STATE_COOKIE), flow.state)) {
      clearCookie(response, LOGIN_STATE_COOKIE, baseUrl);
      return response
        .status(400)
        .type('html')
        .send(
          '<!doctype html><html><title>Sign in failed</title><body><p>Sign-in request expired. Start again.</p></body></html>',
        );
    }
    try {
      return await completeCallback(flow, new URL(request.originalUrl, baseUrl), response);
    } catch {
      flows.delete(flow.state);
      clearCookie(response, LOGIN_STATE_COOKIE, baseUrl);
      return response
        .status(401)
        .type('html')
        .send(
          '<!doctype html><html><title>Sign in failed</title><body><p>Sign-in could not be completed.</p><a href="/login">Try again</a></body></html>',
        );
    }
  });

  app.get('/protected', async (request, response) => {
    const found = getSession(request);
    if (!found) {
      clearCookie(response, BFF_SESSION_COOKIE, baseUrl);
      return response.status(401).json({ error: 'Authentication required.' });
    }
    try {
      let session = found.session;
      if (session.accessTokenExpiresAt <= Date.now() && session.refreshToken) {
        const refreshed = await oidc.refreshTokenGrant(configuration, session.refreshToken);
        if (!refreshed.access_token) throw new Error('Refresh token response was incomplete');
        session = {
          ...session,
          accessToken: refreshed.access_token,
          ...(refreshed.refresh_token ? { refreshToken: refreshed.refresh_token } : {}),
          accessTokenExpiresAt: Date.now() + Number(refreshed.expires_in ?? 600) * 1000,
        };
        sessions.set(found.key, session);
      }
      const userInfo = await oidc.fetchUserInfo(
        configuration,
        session.accessToken,
        session.subject,
      );
      return response.status(200).json({
        sub: userInfo.sub,
        ...(typeof userInfo.email === 'string' ? { email: userInfo.email } : {}),
        ...(typeof userInfo.email_verified === 'boolean'
          ? { email_verified: userInfo.email_verified }
          : {}),
      });
    } catch {
      sessions.delete(found.key);
      clearCookie(response, BFF_SESSION_COOKIE, baseUrl);
      return response.status(401).json({ error: 'Authentication required.' });
    }
  });

  app.post('/logout', async (request, response) => {
    const found = getSession(request);
    if (!found || !constantTimeEqual(request.body.csrf, found.session.csrfToken)) {
      return response.status(403).json({ error: 'Logout request rejected.' });
    }
    sessions.delete(found.key);
    const state = oidc.randomState();
    logoutStates.set(state, Date.now() + FLOW_TTL_MS);
    clearCookie(response, BFF_SESSION_COOKIE, baseUrl);
    const logoutUrl = oidc.buildEndSessionUrl(configuration, {
      id_token_hint: found.session.idToken,
      post_logout_redirect_uri: logoutCallbackUri,
      state,
    });
    return response.redirect(303, logoutUrl.href);
  });

  app.get('/logout/callback', (request, response) => {
    const state = typeof request.query.state === 'string' ? request.query.state : '';
    const expiresAt = logoutStates.get(state);
    if (!expiresAt || expiresAt < Date.now()) {
      logoutStates.delete(state);
      clearCookie(response, BFF_SESSION_COOKIE, baseUrl);
      return response
        .status(400)
        .type('html')
        .send(
          '<!doctype html><html><title>Signed out</title><body><p>Logout request expired.</p></body></html>',
        );
    }
    logoutStates.delete(state);
    clearCookie(response, BFF_SESSION_COOKIE, baseUrl);
    return response
      .status(200)
      .type('html')
      .send(
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>Signed out</title><body><p>You have been signed out.</p><a href="/">Return to the reference BFF</a></body></html>',
      );
  });

  app.use((_request, response) => response.status(404).json({ error: 'Not found.' }));
  app.use((_error: unknown, _request: Request, response: Response, next: express.NextFunction) => {
    void next;
    response.status(500).json({ error: 'Internal server error.' });
  });

  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [state, flow] of flows) if (now - flow.createdAt > FLOW_TTL_MS) flows.delete(state);
    for (const [sessionKey, session] of sessions)
      if (session.expiresAt <= now) sessions.delete(sessionKey);
    for (const [state, expiry] of logoutStates) if (expiry <= now) logoutStates.delete(state);
  }, 60_000);
  sweep.unref();

  return { app, close: () => clearInterval(sweep) };
}

async function start(): Promise<void> {
  const port = Number(process.env.BFF_PORT ?? 4300);
  const runtime = await createBffRuntime();
  const server = runtime.app.listen(port, '127.0.0.1', () => {
    process.stdout.write(`Reference BFF listening on http://127.0.0.1:${port}\n`);
  });
  const shutdown = (): void => {
    server.close(() => runtime.close());
  };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  void start().catch(() => {
    process.stderr.write('Reference BFF startup failed. Check local OIDC configuration.\n');
    process.exitCode = 1;
  });
}
