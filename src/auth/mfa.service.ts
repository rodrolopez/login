import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { Pool } from 'pg';
import argon2 from 'argon2';
import { generateSecret, generateURI, verify } from 'otplib';
import { IdentityRepository } from '../identity/identity.repository.js';
import { ARGON2ID_OPTIONS } from './passwords.js';
import { MfaRepository } from './mfa.repository.js';

const RECOVERY_CODE_COUNT = 10;
const TOTP_PERIOD_SECONDS = 30;
const TOTP_ISSUER = 'Identity API';

export interface TotpEnrollment {
  secret: string;
  otpauthUri: string;
}

export interface TotpConfirmation {
  recoveryCodes: string[];
}

function readEncryptionKey(encoded: string | undefined): Buffer | undefined {
  if (encoded === undefined || encoded === '') return undefined;
  if (!/^[a-fA-F0-9]{64}$/.test(encoded)) {
    throw new Error('MFA encryption key must be a 32-byte hexadecimal value');
  }
  return Buffer.from(encoded, 'hex');
}

function encryptSecret(secret: string, key: Buffer) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const ciphertext = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  return { ciphertext, nonce, authTag: cipher.getAuthTag() };
}

function decryptSecret(ciphertext: Buffer, nonce: Buffer, authTag: Buffer, key: Buffer): string {
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

function newRecoveryCode(): string {
  const value = randomBytes(12).toString('hex').toUpperCase();
  return `${value.slice(0, 8)}-${value.slice(8, 16)}-${value.slice(16)}`;
}

function normalizeRecoveryCode(code: string): string {
  return code.replaceAll('-', '').toUpperCase();
}

export class MfaService {
  private readonly repository: MfaRepository;
  private readonly identities: IdentityRepository;
  private readonly encryptionKey: Buffer | undefined;

  constructor(pool: Pool, encryptionKey?: string) {
    this.repository = new MfaRepository(pool);
    this.identities = new IdentityRepository(pool);
    this.encryptionKey = readEncryptionKey(encryptionKey);
  }

  async isTotpEnabled(userId: string): Promise<boolean> {
    return (await this.repository.findTotpCredential(userId))?.status === 'active';
  }

  isEncryptionConfigured(): boolean {
    return this.encryptionKey !== undefined;
  }

  async beginTotpEnrollment(userId: string): Promise<TotpEnrollment | undefined> {
    if (!this.encryptionKey) throw new Error('MFA encryption is not configured');
    const account = await this.identities.findAccountById(userId);
    const primaryEmail = account?.emails.find((email) => email.isPrimary)?.email;
    if (!account || account.status !== 'active' || !primaryEmail) return undefined;

    const secret = generateSecret();
    const encrypted = encryptSecret(secret, this.encryptionKey);
    const stored = await this.repository.savePendingTotpCredential(
      userId,
      encrypted.ciphertext,
      encrypted.nonce,
      encrypted.authTag,
    );
    if (!stored) return undefined;

    return {
      secret,
      otpauthUri: generateURI({ issuer: TOTP_ISSUER, label: primaryEmail, secret }),
    };
  }

  async confirmTotpEnrollment(
    userId: string,
    token: string,
  ): Promise<TotpConfirmation | undefined> {
    const credential = await this.repository.findTotpCredential(userId);
    if (!credential || credential.status !== 'pending') return undefined;

    let secret: string;
    try {
      secret = decryptSecret(
        credential.encryptedSecret,
        credential.nonce,
        credential.authTag,
        this.encryptionKey!,
      );
    } catch {
      return undefined;
    }
    const verification = await verify({ secret, token, epochTolerance: TOTP_PERIOD_SECONDS });
    if (!verification.valid || !('epoch' in verification)) return undefined;

    const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, newRecoveryCode);
    const codeHashes: string[] = [];
    for (const code of recoveryCodes) {
      codeHashes.push(await argon2.hash(normalizeRecoveryCode(code), ARGON2ID_OPTIONS));
    }
    const counter = BigInt(Math.floor(verification.epoch / TOTP_PERIOD_SECONDS));
    const activated = await this.repository.activateTotpAndSaveRecoveryCodes(
      userId,
      codeHashes,
      counter,
    );
    if (!activated) return undefined;
    return { recoveryCodes };
  }

  async verifyTotp(userId: string, token: string): Promise<boolean> {
    if (!this.encryptionKey) return false;
    const credential = await this.repository.findTotpCredential(userId);
    if (!credential || credential.status !== 'active') return false;

    let secret: string;
    try {
      secret = decryptSecret(
        credential.encryptedSecret,
        credential.nonce,
        credential.authTag,
        this.encryptionKey!,
      );
    } catch {
      return false;
    }
    const verification = await verify({ secret, token, epochTolerance: TOTP_PERIOD_SECONDS });
    if (!verification.valid || !('epoch' in verification)) return false;
    const counter = BigInt(Math.floor(verification.epoch / TOTP_PERIOD_SECONDS));
    return this.repository.recordTotpCounter(userId, counter);
  }

  async consumeRecoveryCode(userId: string, code: string): Promise<boolean> {
    const hashes = await this.repository.availableRecoveryCodeHashes(userId);
    const candidate = normalizeRecoveryCode(code);
    for (const hash of hashes) {
      if (!(await argon2.verify(hash, candidate))) continue;
      return this.repository.consumeRecoveryCode(userId, hash);
    }
    return false;
  }
}
