import type { Pool } from 'pg';
import { withTransaction } from '../infrastructure/postgres/pool.js';

export type AccountActionPurpose = 'email_verification' | 'password_recovery';

export interface AccountActionEmailTarget {
  userId: string;
  emailId: string;
  email: string;
  accountStatus: string;
  emailVerified: boolean;
  hasPasswordCredential: boolean;
}

export class AccountActionRepository {
  constructor(private readonly pool: Pool) {}

  async findEmailTarget(email: string): Promise<AccountActionEmailTarget | undefined> {
    const result = await this.pool.query<{
      user_id: string;
      email_id: string;
      email: string;
      account_status: string;
      email_verified: boolean;
      has_password_credential: boolean;
    }>(
      `SELECT u.id AS user_id, e.id AS email_id, e.email, u.account_status,
              (e.verified_at IS NOT NULL) AS email_verified,
              (c.user_id IS NOT NULL) AS has_password_credential
       FROM identity_api.user_emails AS e
       JOIN identity_api.users AS u ON u.id = e.user_id
       LEFT JOIN identity_api.password_credentials AS c ON c.user_id = u.id
       WHERE lower(e.email) = lower($1) AND e.is_primary = true
       LIMIT 1`,
      [email.trim().toLowerCase()],
    );
    const row = result.rows[0];
    return row
      ? {
          userId: row.user_id,
          emailId: row.email_id,
          email: row.email,
          accountStatus: row.account_status,
          emailVerified: row.email_verified,
          hasPasswordCredential: row.has_password_credential,
        }
      : undefined;
  }

  async issueToken(input: {
    userId: string;
    emailId: string;
    purpose: AccountActionPurpose;
    tokenHash: string;
    expiresInSeconds: number;
  }): Promise<boolean> {
    return withTransaction(this.pool, async (client) => {
      const target = await client.query<{
        account_status: string;
        verified_at: Date | null;
        password_user_id: string | null;
      }>(
        `SELECT u.account_status, e.verified_at, c.user_id AS password_user_id
         FROM identity_api.users AS u
         JOIN identity_api.user_emails AS e ON e.user_id = u.id AND e.id = $2
         LEFT JOIN identity_api.password_credentials AS c ON c.user_id = u.id
         WHERE u.id = $1 AND e.is_primary = true
         FOR UPDATE OF u, e`,
        [input.userId, input.emailId],
      );
      const row = target.rows[0];
      if (!row || !['pending', 'active'].includes(row.account_status)) return false;
      if (
        input.purpose === 'email_verification' &&
        (row.verified_at !== null || row.account_status !== 'pending')
      ) {
        return false;
      }
      if (
        input.purpose === 'password_recovery' &&
        (!row.verified_at || row.account_status !== 'active' || !row.password_user_id)
      ) {
        return false;
      }

      await client.query(
        `UPDATE identity_api.account_action_tokens
         SET consumed_at = now()
         WHERE user_id = $1 AND purpose = $2 AND consumed_at IS NULL`,
        [input.userId, input.purpose],
      );
      const inserted = await client.query(
        `INSERT INTO identity_api.account_action_tokens
           (user_id, email_id, purpose, token_hash, expires_at)
         VALUES ($1, $2, $3, $4, now() + ($5::int * interval '1 second'))`,
        [input.userId, input.emailId, input.purpose, input.tokenHash, input.expiresInSeconds],
      );
      return inserted.rowCount === 1;
    });
  }

  async consumeEmailVerificationToken(tokenHash: string): Promise<string | undefined> {
    return withTransaction(this.pool, async (client) => {
      const selected = await client.query<{
        id: string;
        user_id: string;
        email_id: string;
        account_status: string;
        verified_at: Date | null;
      }>(
        `SELECT t.id, t.user_id, t.email_id, u.account_status, e.verified_at
         FROM identity_api.account_action_tokens AS t
         JOIN identity_api.users AS u ON u.id = t.user_id
         JOIN identity_api.user_emails AS e ON e.id = t.email_id AND e.user_id = t.user_id
         WHERE t.token_hash = $1 AND t.purpose = 'email_verification'
           AND t.consumed_at IS NULL AND t.expires_at > now()
         FOR UPDATE OF t, u, e`,
        [tokenHash],
      );
      const row = selected.rows[0];
      if (!row || !['pending', 'active'].includes(row.account_status) || row.verified_at !== null) {
        return undefined;
      }

      await client.query(
        `UPDATE identity_api.account_action_tokens SET consumed_at = now() WHERE id = $1`,
        [row.id],
      );
      const verified = await client.query(
        `UPDATE identity_api.user_emails
         SET verified_at = now()
         WHERE id = $1 AND user_id = $2 AND verified_at IS NULL`,
        [row.email_id, row.user_id],
      );
      if (verified.rowCount !== 1) throw new Error('Email verification state changed');
      await client.query(
        `UPDATE identity_api.users
         SET account_status = 'active', updated_at = now()
         WHERE id = $1 AND account_status = 'pending'`,
        [row.user_id],
      );
      await client.query(
        `UPDATE identity_api.account_action_tokens
         SET consumed_at = now()
         WHERE user_id = $1 AND purpose = 'email_verification' AND consumed_at IS NULL`,
        [row.user_id],
      );
      return row.user_id;
    });
  }

  async consumePasswordRecoveryToken(input: {
    tokenHash: string;
    passwordHash: string;
  }): Promise<string | undefined> {
    return withTransaction(this.pool, async (client) => {
      const selected = await client.query<{
        id: string;
        user_id: string;
        account_status: string;
        verified_at: Date | null;
      }>(
        `SELECT t.id, t.user_id, u.account_status, e.verified_at
         FROM identity_api.account_action_tokens AS t
         JOIN identity_api.users AS u ON u.id = t.user_id
         JOIN identity_api.user_emails AS e ON e.id = t.email_id AND e.user_id = t.user_id
         JOIN identity_api.password_credentials AS c ON c.user_id = t.user_id
         WHERE t.token_hash = $1 AND t.purpose = 'password_recovery'
           AND t.consumed_at IS NULL AND t.expires_at > now()
         FOR UPDATE OF t, u, e, c`,
        [input.tokenHash],
      );
      const row = selected.rows[0];
      if (!row || row.account_status !== 'active' || row.verified_at === null) {
        return undefined;
      }

      await client.query(
        `UPDATE identity_api.password_credentials
         SET password_hash = $2, updated_at = now()
         WHERE user_id = $1`,
        [row.user_id, input.passwordHash],
      );
      await client.query(
        `UPDATE identity_api.account_action_tokens
         SET consumed_at = now()
         WHERE user_id = $1 AND consumed_at IS NULL`,
        [row.user_id],
      );
      return row.user_id;
    });
  }
}
