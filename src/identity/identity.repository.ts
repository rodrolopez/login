import type { Pool, PoolClient } from 'pg';
import { withTransaction } from '../infrastructure/postgres/pool.js';
import type {
  AccountStatus,
  CreateAccountInput,
  CreateFederatedAccountInput,
  ExternalIdentity,
  LinkExternalIdentityInput,
  PasswordCredential,
  UserAccount,
  UserEmail,
} from './types.js';

interface UserRow {
  id: string;
  account_status: AccountStatus;
  created_at: Date;
  updated_at: Date;
  disabled_at: Date | null;
  anonymized_at: Date | null;
}

interface EmailRow {
  id: string;
  email: string;
  verified_at: Date | null;
  is_primary: boolean;
  created_at: Date;
}

interface CredentialRow {
  user_id: string;
  password_hash: string;
  created_at: Date;
  updated_at: Date;
}

export interface LoginCredentialRecord {
  userId: string;
  accountStatus: AccountStatus;
  passwordHash: string | undefined;
  emailVerified: boolean;
}

interface ExternalIdentityRow {
  id: string;
  user_id: string;
  provider: string;
  issuer: string;
  subject: string;
  created_at: Date;
}

function toEmail(row: EmailRow): UserEmail {
  return {
    id: row.id,
    email: row.email,
    verifiedAt: row.verified_at,
    isPrimary: row.is_primary,
    createdAt: row.created_at,
  };
}

function toAccount(row: UserRow, emails: UserEmail[]): UserAccount {
  return {
    id: row.id,
    status: row.account_status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    disabledAt: row.disabled_at,
    anonymizedAt: row.anonymized_at,
    emails,
  };
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function isArgon2idEncodedHash(value: string): boolean {
  return /^\$argon2id\$v=19\$m=\d+,(?:p=\d+,t=\d+|t=\d+,p=\d+)\$[A-Za-z0-9+/]{8,}={0,2}\$[A-Za-z0-9+/]{16,}={0,2}$/.test(
    value,
  );
}

function toExternalIdentity(row: ExternalIdentityRow): ExternalIdentity {
  return {
    id: row.id,
    userId: row.user_id,
    provider: row.provider,
    issuer: row.issuer,
    subject: row.subject,
    createdAt: row.created_at,
  };
}

export class IdentityRepository {
  constructor(private readonly pool: Pool) {}

  async createAccount(input: CreateAccountInput): Promise<UserAccount> {
    const email = normalizeEmail(input.email);
    if (email.length < 3 || email.length > 320 || !email.includes('@')) {
      throw new Error('Invalid email address');
    }
    if (input.passwordHash !== undefined && !isArgon2idEncodedHash(input.passwordHash)) {
      throw new Error('Password credential must be an Argon2id encoded hash');
    }

    return withTransaction(this.pool, async (client) => {
      const userResult = await client.query<UserRow>(
        `INSERT INTO identity_api.users (account_status)
         VALUES (CASE WHEN $1 THEN 'active' ELSE 'pending' END)
         RETURNING id, account_status, created_at, updated_at, disabled_at, anonymized_at`,
        [input.emailVerified ?? false],
      );
      const user = userResult.rows[0];
      if (!user) throw new Error('Account insert returned no row');

      const emailResult = await client.query<EmailRow>(
        `INSERT INTO identity_api.user_emails (user_id, email, is_primary, verified_at)
         VALUES ($1, $2, true, CASE WHEN $3 THEN now() ELSE NULL END)
         RETURNING id, email, verified_at, is_primary, created_at`,
        [user.id, email, input.emailVerified ?? false],
      );
      const emailRow = emailResult.rows[0];
      if (!emailRow) throw new Error('Email insert returned no row');

      if (input.passwordHash !== undefined) {
        await client.query(
          `INSERT INTO identity_api.password_credentials (user_id, password_hash)
           VALUES ($1, $2)`,
          [user.id, input.passwordHash],
        );
      }

      return toAccount(user, [toEmail(emailRow)]);
    });
  }

  async findAccountById(userId: string): Promise<UserAccount | undefined> {
    const userResult = await this.pool.query<UserRow>(
      `SELECT id, account_status, created_at, updated_at, disabled_at, anonymized_at
       FROM identity_api.users WHERE id = $1`,
      [userId],
    );
    const user = userResult.rows[0];
    if (!user) return undefined;

    const emailResult = await this.pool.query<EmailRow>(
      `SELECT id, email, verified_at, is_primary, created_at
       FROM identity_api.user_emails WHERE user_id = $1 ORDER BY is_primary DESC, created_at`,
      [userId],
    );
    return toAccount(user, emailResult.rows.map(toEmail));
  }

  async findAccountByExternalIdentity(
    issuer: string,
    subject: string,
  ): Promise<UserAccount | undefined> {
    const result = await this.pool.query<UserRow & { user_id: string }>(
      `SELECT u.id, u.id AS user_id, u.account_status, u.created_at, u.updated_at,
              u.disabled_at, u.anonymized_at
       FROM identity_api.external_identities AS x
       JOIN identity_api.users AS u ON u.id = x.user_id
       WHERE x.issuer = $1 AND x.subject = $2`,
      [issuer, subject],
    );
    const row = result.rows[0];
    if (!row) return undefined;
    return this.findAccountById(row.user_id);
  }

  async createFederatedAccount(input: CreateFederatedAccountInput): Promise<UserAccount> {
    const email = normalizeEmail(input.email);
    if (email.length < 3 || email.length > 320 || !email.includes('@')) {
      throw new Error('Invalid email address');
    }

    return withTransaction(this.pool, async (client) => {
      const userResult = await client.query<UserRow>(
        `INSERT INTO identity_api.users (account_status)
         VALUES (CASE WHEN $1 THEN 'active' ELSE 'pending' END)
         RETURNING id, account_status, created_at, updated_at, disabled_at, anonymized_at`,
        [input.emailVerified],
      );
      const user = userResult.rows[0];
      if (!user) throw new Error('Account insert returned no row');
      const emailResult = await client.query<EmailRow>(
        `INSERT INTO identity_api.user_emails (user_id, email, is_primary, verified_at)
         VALUES ($1, $2, true, CASE WHEN $3 THEN now() ELSE NULL END)
         RETURNING id, email, verified_at, is_primary, created_at`,
        [user.id, email, input.emailVerified],
      );
      const emailRow = emailResult.rows[0];
      if (!emailRow) throw new Error('Email insert returned no row');
      await client.query(
        `INSERT INTO identity_api.external_identities (user_id, provider, issuer, subject)
         VALUES ($1, 'google', $2, $3)`,
        [user.id, input.issuer, input.subject],
      );
      return toAccount(user, [toEmail(emailRow)]);
    });
  }

  async findPasswordCredential(userId: string): Promise<PasswordCredential | undefined> {
    const result = await this.pool.query<CredentialRow>(
      `SELECT user_id, password_hash, created_at, updated_at
       FROM identity_api.password_credentials WHERE user_id = $1`,
      [userId],
    );
    const row = result.rows[0];
    return row
      ? {
          userId: row.user_id,
          passwordHash: row.password_hash,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
        }
      : undefined;
  }

  async findLoginCredentialByEmail(email: string): Promise<LoginCredentialRecord | undefined> {
    const result = await this.pool.query<{
      user_id: string;
      account_status: AccountStatus;
      password_hash: string | null;
      email_verified: boolean;
    }>(
      `SELECT u.id AS user_id, u.account_status, c.password_hash,
              (e.verified_at IS NOT NULL) AS email_verified
       FROM identity_api.user_emails AS e
       JOIN identity_api.users AS u ON u.id = e.user_id
       LEFT JOIN identity_api.password_credentials AS c ON c.user_id = u.id
       WHERE lower(e.email) = $1
       LIMIT 1`,
      [normalizeEmail(email)],
    );
    const row = result.rows[0];
    if (!row) return undefined;
    return {
      userId: row.user_id,
      accountStatus: row.account_status,
      passwordHash: row.password_hash ?? undefined,
      emailVerified: row.email_verified,
    };
  }

  async verifyEmail(userId: string, emailId: string): Promise<boolean> {
    return withTransaction(this.pool, async (client) => {
      const result = await client.query(
        `UPDATE identity_api.user_emails SET verified_at = COALESCE(verified_at, now())
         WHERE user_id = $1 AND id = $2`,
        [userId, emailId],
      );
      if (result.rowCount === 1) {
        await client.query(
          `UPDATE identity_api.users SET account_status = 'active', updated_at = now()
           WHERE id = $1 AND account_status = 'pending'`,
          [userId],
        );
      }
      return result.rowCount === 1;
    });
  }

  async linkExternalIdentity(input: LinkExternalIdentityInput): Promise<ExternalIdentity> {
    return withTransaction(this.pool, async (client) => {
      const user = await client.query<{ id: string }>(
        `SELECT id FROM identity_api.users
         WHERE id = $1 AND account_status IN ('pending', 'active')
         FOR UPDATE`,
        [input.userId],
      );
      if (!user.rows[0]) throw new Error('Account is unavailable for identity linking');

      const result = await client.query<ExternalIdentityRow>(
        `INSERT INTO identity_api.external_identities (user_id, provider, issuer, subject)
         VALUES ($1, $2, $3, $4)
         RETURNING id, user_id, provider, issuer, subject, created_at`,
        [input.userId, input.provider.toLowerCase(), input.issuer, input.subject],
      );
      const row = result.rows[0];
      if (!row) throw new Error('External identity insert returned no row');
      return toExternalIdentity(row);
    });
  }

  async disableAccount(userId: string): Promise<boolean> {
    const result = await this.pool.query(
      `UPDATE identity_api.users
       SET account_status = 'disabled', disabled_at = COALESCE(disabled_at, now()), updated_at = now()
       WHERE id = $1 AND account_status <> 'anonymized'`,
      [userId],
    );
    return result.rowCount === 1;
  }

  async suspendAccount(userId: string): Promise<boolean> {
    const result = await this.pool.query(
      `UPDATE identity_api.users
       SET account_status = 'suspended', disabled_at = NULL, updated_at = now()
       WHERE id = $1 AND account_status <> 'anonymized'`,
      [userId],
    );
    return result.rowCount === 1;
  }

  async anonymizeAccount(userId: string): Promise<boolean> {
    return withTransaction(this.pool, async (client: PoolClient) => {
      const userResult = await client.query<{ id: string; account_status: AccountStatus }>(
        `SELECT id, account_status FROM identity_api.users WHERE id = $1 FOR UPDATE`,
        [userId],
      );
      const user = userResult.rows[0];
      if (!user) return false;
      if (user.account_status === 'anonymized') return true;

      await client.query('DELETE FROM identity_api.user_emails WHERE user_id = $1', [userId]);
      await client.query('DELETE FROM identity_api.password_credentials WHERE user_id = $1', [
        userId,
      ]);
      await client.query('DELETE FROM identity_api.external_identities WHERE user_id = $1', [
        userId,
      ]);
      await client.query('DELETE FROM identity_api.oidc_grants WHERE account_id = $1', [userId]);
      await client.query(
        `UPDATE identity_api.users
         SET account_status = 'anonymized', disabled_at = NULL, anonymized_at = now(), updated_at = now()
         WHERE id = $1`,
        [userId],
      );
      return true;
    });
  }

  async deleteAnonymizedAccountPermanently(userId: string): Promise<boolean> {
    const result = await this.pool.query(
      `DELETE FROM identity_api.users WHERE id = $1 AND account_status = 'anonymized'`,
      [userId],
    );
    return result.rowCount === 1;
  }
}
