import { createHash, randomBytes } from 'node:crypto';
import type { Pool } from 'pg';
import {
  AccountActionRepository,
  type AccountActionPurpose,
} from '../identity/account-action.repository.js';
import type { EmailProvider } from '../email/email-provider.js';

export const EMAIL_VERIFICATION_TTL_SECONDS = 24 * 60 * 60;
export const PASSWORD_RECOVERY_TTL_SECONDS = 30 * 60;

function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

function validToken(token: string): boolean {
  return /^[A-Za-z0-9_-]{40,64}$/.test(token);
}

export class AccountActionService {
  private readonly repository: AccountActionRepository;

  constructor(
    pool: Pool,
    private readonly emailProvider: EmailProvider,
  ) {
    this.repository = new AccountActionRepository(pool);
  }

  async requestEmailVerification(email: string, language: 'en' | 'es'): Promise<void> {
    await this.requestToken(email, language, 'email_verification');
  }

  async requestPasswordRecovery(email: string, language: 'en' | 'es'): Promise<void> {
    await this.requestToken(email, language, 'password_recovery');
  }

  async verifyEmail(token: string): Promise<string | undefined> {
    if (!validToken(token)) return undefined;
    return this.repository.consumeEmailVerificationToken(hashToken(token));
  }

  async recoverPassword(token: string, passwordHash: string): Promise<string | undefined> {
    if (!validToken(token)) return undefined;
    return this.repository.consumePasswordRecoveryToken({
      tokenHash: hashToken(token),
      passwordHash,
    });
  }

  private async requestToken(
    email: string,
    language: 'en' | 'es',
    purpose: AccountActionPurpose,
  ): Promise<void> {
    const target = await this.repository.findEmailTarget(email);
    if (
      !target ||
      !['pending', 'active'].includes(target.accountStatus) ||
      (purpose === 'email_verification' && target.emailVerified) ||
      (purpose === 'password_recovery' &&
        (!target.emailVerified ||
          target.accountStatus !== 'active' ||
          !target.hasPasswordCredential))
    ) {
      return;
    }

    const token = randomBytes(32).toString('base64url');
    const ttlSeconds =
      purpose === 'email_verification'
        ? EMAIL_VERIFICATION_TTL_SECONDS
        : PASSWORD_RECOVERY_TTL_SECONDS;
    const issued = await this.repository.issueToken({
      userId: target.userId,
      emailId: target.emailId,
      purpose,
      tokenHash: hashToken(token),
      expiresInSeconds: ttlSeconds,
    });
    if (!issued) return;

    await this.emailProvider.sendAccountActionEmail({
      purpose,
      recipient: target.email,
      token,
      expiresAt: new Date(Date.now() + ttlSeconds * 1000),
      language,
    });
  }
}
