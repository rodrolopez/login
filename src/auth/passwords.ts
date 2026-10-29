import { randomBytes } from 'node:crypto';
import argon2, { type HashOptions } from 'argon2';

export const ARGON2ID_OPTIONS: HashOptions & { type: typeof argon2.argon2id } = {
  type: argon2.argon2id,
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
  hashLength: 32,
};

export class PasswordService {
  private readonly dummyHashPromise: Promise<string> = argon2.hash(
    randomBytes(32).toString('base64url'),
    ARGON2ID_OPTIONS,
  );

  hash(password: string): Promise<string> {
    return argon2.hash(password, { ...ARGON2ID_OPTIONS, raw: false });
  }

  verify(password: string, encodedHash: string): Promise<boolean> {
    return argon2.verify(encodedHash, password);
  }

  async performDummyVerification(password: string): Promise<void> {
    const dummyHash = await this.dummyHashPromise;
    await argon2.verify(dummyHash, password);
  }
}
