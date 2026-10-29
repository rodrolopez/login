import { timingSafeEqual } from 'node:crypto';
import { Router, type Request, type Response } from 'express';
import type { Redis } from 'ioredis';
import type { Pool } from 'pg';
import type Provider from 'oidc-provider';
import { IdentityRepository } from '../identity/identity.repository.js';
import { completeOidcLogin } from '../oidc/interaction.routes.js';
import { AuthAttemptRateLimiter } from './auth-rate-limiter.js';
import { messages, requestLanguage, type Language, type MessageKey } from './i18n.js';
import { PasswordService } from './passwords.js';
import {
  emailActionRequestSchema,
  emailVerificationConfirmSchema,
  loginBodySchema,
  mfaLoginVerifySchema,
  passwordRecoveryConfirmSchema,
  registerBodySchema,
  totpConfirmSchema,
} from './validation.js';
import {
  ApiSessionService,
  IdentitySessionRevocationService,
} from '../sessions/session.service.js';
import { googleFlowCrypto, GOOGLE_ISSUER, type GoogleOidcClient } from './google-oidc-client.js';
import { DisabledEmailProvider, type EmailProvider } from '../email/email-provider.js';
import { AccountActionService } from './account-action.service.js';
import { MfaService } from './mfa.service.js';
import { MfaLoginChallengeService } from './mfa-login-challenge.service.js';

const GOOGLE_FLOW_TTL_SECONDS = 5 * 60;
const GOOGLE_FLOW_PREFIX = 'identity:google:flow';
const GOOGLE_STATE_COOKIE = 'identity_google_state';

function googleStateCookieAttributes(maxAge = GOOGLE_FLOW_TTL_SECONDS): string {
  return `Path=/auth/google/callback; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`;
}

function readGoogleStateCookie(request: Request): string | undefined {
  for (const part of (request.headers.cookie ?? '').split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0 || part.slice(0, separator).trim() !== GOOGLE_STATE_COOKIE) continue;
    try {
      return decodeURIComponent(part.slice(separator + 1).trim());
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function matchesState(left: string, right: string | undefined): boolean {
  if (!right) return false;
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

export interface AuthRouteDependencies {
  pool: Pool;
  redis: Redis;
  rateLimitKeySecret: string;
  mfaEncryptionKey?: string;
  oidcProvider?: Provider;
  googleOidcClient?: GoogleOidcClient;
  googleRedirectUri?: string;
  emailProvider?: EmailProvider;
  corsAllowedOrigins?: string[];
}

function errorCode(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null || !('code' in error)) return undefined;
  return typeof error.code === 'string' ? error.code : undefined;
}

function message(language: Language, key: MessageKey): string {
  return messages[language][key];
}

function sendValidationError(
  response: Response,
  language: Language,
  issues: Array<{ path: PropertyKey[]; message: string }>,
) {
  const fields = [
    ...new Map(
      issues.map((issue) => {
        const field = String(issue.path[0] ?? 'body');
        const knownKey = issue.message as MessageKey;
        const key: MessageKey = Object.hasOwn(messages[language], issue.message)
          ? knownKey
          : field === 'email'
            ? 'invalidEmail'
            : field === 'password'
              ? 'passwordLength'
              : 'validation';
        return [field, { field, message: message(language, key) }] as const;
      }),
    ).values(),
  ];
  return response.status(400).json({ error: message(language, 'validation'), fields });
}

export function createAuthRouter(dependencies: AuthRouteDependencies): Router {
  const router = Router();
  const repository = new IdentityRepository(dependencies.pool);
  const sessions = new ApiSessionService(dependencies.pool, dependencies.redis);
  const emailProvider = dependencies.emailProvider ?? new DisabledEmailProvider();
  const accountActions = new AccountActionService(dependencies.pool, emailProvider);
  const mfa = new MfaService(dependencies.pool, dependencies.mfaEncryptionKey);
  const mfaChallenges = new MfaLoginChallengeService(dependencies.redis);
  const sessionRevocation = new IdentitySessionRevocationService(
    dependencies.pool,
    dependencies.redis,
  );
  const passwords = new PasswordService();
  const loginLimiter = new AuthAttemptRateLimiter(
    dependencies.redis,
    dependencies.rateLimitKeySecret,
  );
  const registerLimiter = new AuthAttemptRateLimiter(
    dependencies.redis,
    dependencies.rateLimitKeySecret,
    5,
    20,
    60 * 60 * 1000,
    'register',
  );
  const verificationRequestLimiter = new AuthAttemptRateLimiter(
    dependencies.redis,
    dependencies.rateLimitKeySecret,
    5,
    30,
    60 * 60 * 1000,
    'email-verification-request',
  );
  const recoveryRequestLimiter = new AuthAttemptRateLimiter(
    dependencies.redis,
    dependencies.rateLimitKeySecret,
    5,
    30,
    60 * 60 * 1000,
    'password-recovery-request',
  );
  const accountActionConfirmLimiter = new AuthAttemptRateLimiter(
    dependencies.redis,
    dependencies.rateLimitKeySecret,
    10,
    40,
    60 * 60 * 1000,
    'account-action-confirm',
  );
  const mfaLoginLimiter = new AuthAttemptRateLimiter(
    dependencies.redis,
    dependencies.rateLimitKeySecret,
    5,
    60,
    15 * 60 * 1000,
    'mfa-login',
  );
  const mfaEnrollmentConfirmLimiter = new AuthAttemptRateLimiter(
    dependencies.redis,
    dependencies.rateLimitKeySecret,
    5,
    30,
    15 * 60 * 1000,
    'mfa-enrollment-confirm',
  );

  router.post('/mfa/totp/enrollment', async (request: Request, response: Response) => {
    const language = requestLanguage(response);
    const userId = await sessions.accountForRequest(request);
    if (!userId) {
      sessions.clearCookie(response);
      return response.status(401).json({ error: message(language, 'invalidCredentials') });
    }
    if (!mfa.isEncryptionConfigured()) {
      return response.status(503).json({ error: message(language, 'unavailable') });
    }
    try {
      const enrollment = await mfa.beginTotpEnrollment(userId);
      if (!enrollment) {
        return response.status(409).json({ error: message(language, 'mfaAlreadyEnabled') });
      }
      return response.status(200).json(enrollment);
    } catch {
      return response.status(503).json({ error: message(language, 'unavailable') });
    }
  });

  router.post('/mfa/totp/confirm', async (request: Request, response: Response) => {
    const language = requestLanguage(response);
    const userId = await sessions.accountForRequest(request);
    if (!userId) {
      sessions.clearCookie(response);
      return response.status(401).json({ error: message(language, 'invalidCredentials') });
    }
    const parsed = totpConfirmSchema.safeParse(request.body);
    if (!parsed.success) {
      return response.status(400).json({ error: message(language, 'validation') });
    }
    if (!mfa.isEncryptionConfigured()) {
      return response.status(503).json({ error: message(language, 'unavailable') });
    }
    let decision;
    try {
      decision = await mfaEnrollmentConfirmLimiter.consume(
        request.ip ?? request.socket.remoteAddress ?? 'unknown',
        userId,
      );
    } catch {
      return response.status(503).json({ error: message(language, 'unavailable') });
    }
    if (!decision.allowed) {
      response.setHeader('Retry-After', String(decision.retryAfterSeconds));
      return response.status(429).json({ error: message(language, 'rateLimited') });
    }
    try {
      const confirmation = await mfa.confirmTotpEnrollment(userId, parsed.data.token);
      if (!confirmation) {
        return response.status(400).json({ error: message(language, 'mfaInvalid') });
      }
      return response.status(200).json(confirmation);
    } catch {
      return response.status(503).json({ error: message(language, 'unavailable') });
    }
  });

  router.post('/mfa/totp/verify', async (request: Request, response: Response) => {
    const language = requestLanguage(response);
    const parsed = mfaLoginVerifySchema.safeParse(request.body);
    if (!parsed.success) {
      return response.status(400).json({ error: message(language, 'validation') });
    }

    try {
      const challenge = await mfaChallenges.find(parsed.data.challengeId);
      if (!challenge) {
        return response.status(401).json({ error: message(language, 'mfaInvalid') });
      }
      if (!mfa.isEncryptionConfigured()) {
        return response.status(503).json({ error: message(language, 'unavailable') });
      }

      const decision = await mfaLoginLimiter.consume(
        request.ip ?? request.socket.remoteAddress ?? 'unknown',
        challenge.userId,
      );
      if (!decision.allowed) {
        response.setHeader('Retry-After', String(decision.retryAfterSeconds));
        return response.status(429).json({ error: message(language, 'rateLimited') });
      }

      const challengedAccount = await repository.findAccountById(challenge.userId);
      if (
        !challengedAccount ||
        challengedAccount.status !== 'active' ||
        !challengedAccount.emails.some((email) => email.isPrimary && email.verifiedAt !== null)
      ) {
        return response.status(401).json({ error: message(language, 'mfaInvalid') });
      }

      const valid = parsed.data.token
        ? await mfa.verifyTotp(challenge.userId, parsed.data.token)
        : await mfa.consumeRecoveryCode(challenge.userId, parsed.data.recoveryCode!);
      if (!valid) return response.status(401).json({ error: message(language, 'mfaInvalid') });
      if (!(await mfaChallenges.consume(parsed.data.challengeId, challenge))) {
        return response.status(401).json({ error: message(language, 'mfaInvalid') });
      }

      if (challenge.interactionUid) {
        if (
          !dependencies.oidcProvider ||
          !(await completeOidcLogin(
            dependencies.oidcProvider,
            repository,
            request,
            response,
            challenge.interactionUid,
            challenge.userId,
          ))
        ) {
          return response.status(400).json({ error: message(language, 'validation') });
        }
        return;
      }

      const sessionToken = await sessions.create(challenge.userId);
      sessions.setCookie(response, sessionToken);
      return response.status(200).json({ userId: challenge.userId });
    } catch {
      return response.status(503).json({ error: message(language, 'unavailable') });
    }
  });

  const genericActionAccepted = (response: Response, language: Language) =>
    response.status(202).json({ message: message(language, 'accountActionAccepted') });

  router.post('/email/verification/request', async (request: Request, response: Response) => {
    const language = requestLanguage(response);
    const parsed = emailActionRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return response.status(400).json({ error: message(language, 'validation') });
    }
    try {
      const limit = await verificationRequestLimiter.consume(
        request.ip ?? request.socket.remoteAddress ?? 'unknown',
        parsed.data.email,
      );
      if (limit.allowed) await accountActions.requestEmailVerification(parsed.data.email, language);
    } catch {
      process.stderr.write('account_action.request_unavailable purpose=email_verification\n');
    }
    return genericActionAccepted(response, language);
  });

  router.post('/email/verification/confirm', async (request: Request, response: Response) => {
    const language = requestLanguage(response);
    const parsed = emailVerificationConfirmSchema.safeParse(request.body);
    if (!parsed.success) {
      return response.status(400).json({ error: message(language, 'accountActionInvalid') });
    }
    try {
      const limit = await accountActionConfirmLimiter.consume(
        request.ip ?? request.socket.remoteAddress ?? 'unknown',
        parsed.data.token,
      );
      if (!limit.allowed || !(await accountActions.verifyEmail(parsed.data.token))) {
        return response.status(400).json({ error: message(language, 'accountActionInvalid') });
      }
      return response.status(200).json({ message: message(language, 'emailVerificationComplete') });
    } catch {
      return response.status(503).json({ error: message(language, 'unavailable') });
    }
  });

  router.post('/password/recovery/request', async (request: Request, response: Response) => {
    const language = requestLanguage(response);
    const parsed = emailActionRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return response.status(400).json({ error: message(language, 'validation') });
    }
    try {
      const limit = await recoveryRequestLimiter.consume(
        request.ip ?? request.socket.remoteAddress ?? 'unknown',
        parsed.data.email,
      );
      if (limit.allowed) await accountActions.requestPasswordRecovery(parsed.data.email, language);
    } catch {
      process.stderr.write('account_action.request_unavailable purpose=password_recovery\n');
    }
    return genericActionAccepted(response, language);
  });

  router.post('/password/recovery/confirm', async (request: Request, response: Response) => {
    const language = requestLanguage(response);
    const parsed = passwordRecoveryConfirmSchema.safeParse(request.body);
    if (!parsed.success) {
      return response.status(400).json({ error: message(language, 'accountActionInvalid') });
    }
    try {
      const limit = await accountActionConfirmLimiter.consume(
        request.ip ?? request.socket.remoteAddress ?? 'unknown',
        parsed.data.token,
      );
      if (!limit.allowed) {
        return response.status(400).json({ error: message(language, 'accountActionInvalid') });
      }
      const passwordHash = await passwords.hash(parsed.data.password);
      const userId = await accountActions.recoverPassword(parsed.data.token, passwordHash);
      if (!userId) {
        return response.status(400).json({ error: message(language, 'accountActionInvalid') });
      }
      await sessionRevocation.revokeAccountSessions(userId);
      return response.status(200).json({ message: message(language, 'passwordRecoveryComplete') });
    } catch {
      return response.status(503).json({ error: message(language, 'unavailable') });
    }
  });

  router.get('/google', async (request: Request, response: Response) => {
    if (!dependencies.googleOidcClient) {
      return response
        .status(503)
        .json({ error: message(requestLanguage(response), 'unavailable') });
    }
    const configuredHostname = dependencies.googleRedirectUri
      ? new URL(dependencies.googleRedirectUri).hostname
      : undefined;
    if (configuredHostname && request.hostname.toLowerCase() !== configuredHostname.toLowerCase()) {
      return response
        .status(400)
        .json({ error: message(requestLanguage(response), 'googleFailure') });
    }
    const state = googleFlowCrypto.randomState();
    const nonce = googleFlowCrypto.randomNonce();
    const codeVerifier = googleFlowCrypto.randomCodeVerifier();
    try {
      const url = await dependencies.googleOidcClient.authorizationUrl({
        state,
        nonce,
        codeVerifier,
      });
      const stored = await dependencies.redis.set(
        `${GOOGLE_FLOW_PREFIX}:${state}`,
        JSON.stringify({ nonce, codeVerifier }),
        'EX',
        GOOGLE_FLOW_TTL_SECONDS,
        'NX',
      );
      if (stored !== 'OK') throw new Error('Unable to persist Google authorization state');
      response.append(
        'Set-Cookie',
        `${GOOGLE_STATE_COOKIE}=${encodeURIComponent(state)}; ${googleStateCookieAttributes()}`,
      );
      return response.redirect(302, url);
    } catch {
      return response
        .status(503)
        .json({ error: message(requestLanguage(response), 'unavailable') });
    }
  });

  router.get('/google/callback', async (request: Request, response: Response) => {
    const language = requestLanguage(response);
    response.append(
      'Set-Cookie',
      `${GOOGLE_STATE_COOKIE}=; ${googleStateCookieAttributes(0)}; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
    );
    const state = typeof request.query.state === 'string' ? request.query.state : '';
    if (
      !dependencies.googleOidcClient ||
      !state ||
      state.length > 256 ||
      !matchesState(state, readGoogleStateCookie(request))
    ) {
      return response.status(400).json({ error: message(language, 'googleFailure') });
    }
    let rawFlow: string | null;
    try {
      rawFlow = await dependencies.redis.getdel(`${GOOGLE_FLOW_PREFIX}:${state}`);
    } catch {
      return response.status(503).json({ error: message(language, 'unavailable') });
    }
    if (!rawFlow) return response.status(400).json({ error: message(language, 'googleFailure') });

    try {
      const flow = JSON.parse(rawFlow) as { nonce?: unknown; codeVerifier?: unknown };
      if (typeof flow.nonce !== 'string' || typeof flow.codeVerifier !== 'string') {
        return response.status(400).json({ error: message(language, 'googleFailure') });
      }
      if (typeof request.query.error === 'string' || typeof request.query.code !== 'string') {
        return response.status(401).json({ error: message(language, 'googleFailure') });
      }
      const callbackUrl = new URL(
        dependencies.googleRedirectUri ??
          `${request.protocol}://${request.get('host')}/auth/google/callback`,
      );
      for (const [key, value] of Object.entries(request.query)) {
        if (typeof value === 'string') callbackUrl.searchParams.set(key, value);
      }
      const identity = await dependencies.googleOidcClient.completeAuthorization({
        callbackUrl,
        expectedState: state,
        expectedNonce: flow.nonce,
        codeVerifier: flow.codeVerifier,
      });
      if (!identity.emailVerified) {
        return response.status(401).json({ error: message(language, 'googleFailure') });
      }
      const existingIdentity = await repository.findAccountByExternalIdentity(
        GOOGLE_ISSUER,
        identity.subject,
      );
      let accountId: string;
      if (existingIdentity) {
        if (
          existingIdentity.status !== 'active' ||
          !existingIdentity.emails.some((email) => email.isPrimary && email.verifiedAt !== null)
        ) {
          return response.status(401).json({ error: message(language, 'googleFailure') });
        }
        accountId = existingIdentity.id;
      } else {
        const localAccount = await repository.findLoginCredentialByEmail(identity.email);
        if (localAccount) {
          return response.status(409).json({ error: message(language, 'googleLocalAccount') });
        }
        try {
          const account = await repository.createFederatedAccount({
            email: identity.email,
            issuer: GOOGLE_ISSUER,
            subject: identity.subject,
            emailVerified: identity.emailVerified,
          });
          accountId = account.id;
        } catch (error) {
          if (errorCode(error) !== '23505') throw error;
          const racedIdentity = await repository.findAccountByExternalIdentity(
            GOOGLE_ISSUER,
            identity.subject,
          );
          if (
            racedIdentity?.status === 'active' &&
            racedIdentity.emails.some((email) => email.isPrimary && email.verifiedAt !== null)
          ) {
            accountId = racedIdentity.id;
          } else {
            const racedLocalAccount = await repository.findLoginCredentialByEmail(identity.email);
            if (racedLocalAccount) {
              return response.status(409).json({ error: message(language, 'googleLocalAccount') });
            }
            return response.status(409).json({ error: message(language, 'googleFailure') });
          }
        }
      }
      if (await mfa.isTotpEnabled(accountId)) {
        if (!mfa.isEncryptionConfigured()) {
          return response.status(503).json({ error: message(language, 'unavailable') });
        }
        const challengeId = await mfaChallenges.create({ userId: accountId });
        return response.status(202).json({ mfaRequired: true, challengeId });
      }
      const sessionToken = await sessions.create(accountId);
      sessions.setCookie(response, sessionToken);
      return response.status(200).json({ userId: accountId });
    } catch {
      return response.status(502).json({ error: message(language, 'googleFailure') });
    }
  });

  router.get('/session', async (request: Request, response: Response) => {
    try {
      const userId = await sessions.accountForRequest(request);
      if (!userId) {
        sessions.clearCookie(response);
        return response.status(401).json({ error: 'Authentication required.' });
      }
      return response.status(200).json({ userId });
    } catch {
      return response
        .status(503)
        .json({ error: message(requestLanguage(response), 'unavailable') });
    }
  });

  router.post('/logout', async (request: Request, response: Response) => {
    try {
      await sessions.destroyFromRequest(request);
      sessions.clearCookie(response);
      return response.status(204).end();
    } catch {
      sessions.clearCookie(response);
      return response
        .status(503)
        .json({ error: message(requestLanguage(response), 'unavailable') });
    }
  });

  router.post('/register', async (request: Request, response: Response) => {
    const language = requestLanguage(response);
    const parsed = registerBodySchema.safeParse(request.body);
    if (!parsed.success) return sendValidationError(response, language, parsed.error.issues);

    let decision;
    try {
      decision = await registerLimiter.consume(
        request.ip ?? request.socket.remoteAddress ?? 'unknown',
        parsed.data.email,
      );
    } catch {
      return response.status(503).json({ error: message(language, 'unavailable') });
    }
    if (!decision.allowed) {
      response.setHeader('Retry-After', String(decision.retryAfterSeconds));
      return response.status(429).json({ error: message(language, 'rateLimited') });
    }

    const passwordHash = await passwords.hash(parsed.data.password);
    try {
      const account = await repository.createAccount({
        email: parsed.data.email,
        passwordHash,
      });
      try {
        await accountActions.requestEmailVerification(parsed.data.email, language);
      } catch {
        process.stderr.write('account_action.request_unavailable purpose=email_verification\n');
      }
      return response.status(201).json({ userId: account.id });
    } catch (error) {
      if (errorCode(error) === '23505') {
        return response.status(409).json({ error: message(language, 'emailAlreadyUsed') });
      }
      throw error;
    }
  });

  router.post('/login', async (request: Request, response: Response) => {
    const language = requestLanguage(response);
    const parsed = loginBodySchema.safeParse(request.body);
    if (!parsed.success) return sendValidationError(response, language, parsed.error.issues);

    let decision;
    try {
      decision = await loginLimiter.consume(
        request.ip ?? request.socket.remoteAddress ?? 'unknown',
        parsed.data.email,
      );
    } catch {
      return response.status(503).json({ error: message(language, 'unavailable') });
    }
    if (!decision.allowed) {
      response.setHeader('Retry-After', String(decision.retryAfterSeconds));
      return response.status(429).json({ error: message(language, 'rateLimited') });
    }

    const credential = await repository.findLoginCredentialByEmail(parsed.data.email);
    const canAuthenticate =
      credential !== undefined &&
      credential.passwordHash !== undefined &&
      credential.emailVerified &&
      credential.accountStatus === 'active';

    let isValid = false;
    if (canAuthenticate && credential.passwordHash) {
      try {
        isValid = await passwords.verify(parsed.data.password, credential.passwordHash);
      } catch {
        isValid = false;
      }
    } else {
      await passwords.performDummyVerification(parsed.data.password);
    }

    if (!isValid || !credential) {
      return response.status(401).json({ error: message(language, 'invalidCredentials') });
    }

    try {
      if (await mfa.isTotpEnabled(credential.userId)) {
        if (!mfa.isEncryptionConfigured()) {
          return response.status(503).json({ error: message(language, 'unavailable') });
        }
        const challengeId = await mfaChallenges.create({
          userId: credential.userId,
          ...(parsed.data.interactionUid ? { interactionUid: parsed.data.interactionUid } : {}),
        });
        return response.status(202).json({ mfaRequired: true, challengeId });
      }
    } catch {
      return response.status(503).json({ error: message(language, 'unavailable') });
    }

    if (parsed.data.interactionUid) {
      if (
        !dependencies.oidcProvider ||
        !(await completeOidcLogin(
          dependencies.oidcProvider,
          repository,
          request,
          response,
          parsed.data.interactionUid,
          credential.userId,
        ))
      ) {
        return response.status(400).json({ error: message(language, 'validation') });
      }
      return;
    }

    try {
      const sessionToken = await sessions.create(credential.userId);
      sessions.setCookie(response, sessionToken);
    } catch {
      return response.status(503).json({ error: message(language, 'unavailable') });
    }
    return response.status(200).json({ userId: credential.userId });
  });

  return router;
}
