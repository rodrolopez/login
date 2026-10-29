export type AccountStatus = 'pending' | 'active' | 'suspended' | 'disabled' | 'anonymized';

export interface UserAccount {
  id: string;
  status: AccountStatus;
  createdAt: Date;
  updatedAt: Date;
  disabledAt: Date | null;
  anonymizedAt: Date | null;
  emails: UserEmail[];
}

export interface UserEmail {
  id: string;
  email: string;
  verifiedAt: Date | null;
  isPrimary: boolean;
  createdAt: Date;
}

export interface PasswordCredential {
  userId: string;
  passwordHash: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface ExternalIdentity {
  id: string;
  userId: string;
  provider: string;
  issuer: string;
  subject: string;
  createdAt: Date;
}

export interface CreateAccountInput {
  email: string;
  /** A previously generated Argon2id encoded hash; plaintext is rejected. */
  passwordHash?: string;
  emailVerified?: boolean;
}

export interface CreateFederatedAccountInput {
  email: string;
  issuer: string;
  subject: string;
  emailVerified: boolean;
}

export interface LinkExternalIdentityInput {
  userId: string;
  provider: string;
  issuer: string;
  subject: string;
}
