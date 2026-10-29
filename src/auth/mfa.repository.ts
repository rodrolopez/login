import type { Pool } from 'pg';
import { withTransaction } from '../infrastructure/postgres/pool.js';

export type TotpCredentialStatus = 'pending' | 'active';

export interface TotpCredential {
  encryptedSecret: Buffer;
  nonce: Buffer;
  authTag: Buffer;
  status: TotpCredentialStatus;
  lastTotpCounter: bigint | undefined;
}

export class MfaRepository {
  constructor(private readonly pool: Pool) {}

  async findTotpCredential(userId: string): Promise<TotpCredential | undefined> {
    const result = await this.pool.query<{
      secret_ciphertext: Buffer;
      secret_nonce: Buffer;
      secret_auth_tag: Buffer;
      status: TotpCredentialStatus;
      last_totp_counter: string | null;
    }>(
      `SELECT secret_ciphertext, secret_nonce, secret_auth_tag, status, last_totp_counter
       FROM identity_api.user_totp_credentials
       WHERE user_id = $1 AND (status = 'active' OR enrollment_expires_at > now())`,
      [userId],
    );
    const row = result.rows[0];
    if (!row) return undefined;
    return {
      encryptedSecret: row.secret_ciphertext,
      nonce: row.secret_nonce,
      authTag: row.secret_auth_tag,
      status: row.status,
      lastTotpCounter: row.last_totp_counter === null ? undefined : BigInt(row.last_totp_counter),
    };
  }

  async savePendingTotpCredential(
    userId: string,
    encryptedSecret: Buffer,
    nonce: Buffer,
    authTag: Buffer,
  ): Promise<boolean> {
    const result = await this.pool.query(
      `INSERT INTO identity_api.user_totp_credentials
         (user_id, secret_ciphertext, secret_nonce, secret_auth_tag, status, enrollment_expires_at)
       VALUES ($1, $2, $3, $4, 'pending', now() + interval '15 minutes')
       ON CONFLICT (user_id) DO UPDATE
         SET secret_ciphertext = EXCLUDED.secret_ciphertext,
             secret_nonce = EXCLUDED.secret_nonce,
             secret_auth_tag = EXCLUDED.secret_auth_tag,
             created_at = now(),
             enrollment_expires_at = now() + interval '15 minutes'
       WHERE identity_api.user_totp_credentials.status = 'pending'
       RETURNING user_id`,
      [userId, encryptedSecret, nonce, authTag],
    );
    return result.rowCount === 1;
  }

  async activateTotpAndSaveRecoveryCodes(
    userId: string,
    codeHashes: string[],
    initialCounter: bigint,
  ): Promise<boolean> {
    return withTransaction(this.pool, async (client) => {
      const credential = await client.query<{ status: TotpCredentialStatus }>(
        `SELECT status FROM identity_api.user_totp_credentials
         WHERE user_id = $1 FOR UPDATE`,
        [userId],
      );
      if (credential.rows[0]?.status !== 'pending') return false;

      const activated = await client.query(
        `UPDATE identity_api.user_totp_credentials
         SET status = 'active', confirmed_at = now(), last_totp_counter = $2,
             enrollment_expires_at = NULL
         WHERE user_id = $1 AND status = 'pending' AND enrollment_expires_at > now()`,
        [userId, initialCounter.toString()],
      );
      if (activated.rowCount !== 1) return false;

      for (const codeHash of codeHashes) {
        await client.query(
          `INSERT INTO identity_api.user_mfa_recovery_codes (user_id, code_hash)
           VALUES ($1, $2)`,
          [userId, codeHash],
        );
      }
      return true;
    });
  }

  async availableRecoveryCodeHashes(userId: string): Promise<string[]> {
    const result = await this.pool.query<{ code_hash: string }>(
      `SELECT code_hash FROM identity_api.user_mfa_recovery_codes
       WHERE user_id = $1 AND consumed_at IS NULL ORDER BY created_at`,
      [userId],
    );
    return result.rows.map((row) => row.code_hash);
  }

  async consumeRecoveryCode(userId: string, codeHash: string): Promise<boolean> {
    const result = await this.pool.query(
      `UPDATE identity_api.user_mfa_recovery_codes
       SET consumed_at = now()
       WHERE user_id = $1 AND code_hash = $2 AND consumed_at IS NULL`,
      [userId, codeHash],
    );
    return result.rowCount === 1;
  }

  async recordTotpCounter(userId: string, counter: bigint): Promise<boolean> {
    const result = await this.pool.query(
      `UPDATE identity_api.user_totp_credentials
       SET last_totp_counter = $2
       WHERE user_id = $1 AND status = 'active'
         AND (last_totp_counter IS NULL OR last_totp_counter < $2)`,
      [userId, counter.toString()],
    );
    return result.rowCount === 1;
  }
}
