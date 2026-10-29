CREATE TABLE identity_api.user_totp_credentials (
  user_id UUID PRIMARY KEY REFERENCES identity_api.users(id) ON DELETE CASCADE,
  secret_ciphertext BYTEA NOT NULL,
  secret_nonce BYTEA NOT NULL CHECK (octet_length(secret_nonce) = 12),
  secret_auth_tag BYTEA NOT NULL CHECK (octet_length(secret_auth_tag) = 16),
  status TEXT NOT NULL CHECK (status IN ('pending', 'active')),
  last_totp_counter BIGINT,
  enrollment_expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  confirmed_at TIMESTAMPTZ,
  CONSTRAINT user_totp_confirmation_state_check CHECK (
    (status = 'pending' AND confirmed_at IS NULL AND enrollment_expires_at IS NOT NULL) OR
    (status = 'active' AND confirmed_at IS NOT NULL AND enrollment_expires_at IS NULL)
  ),
  CONSTRAINT user_totp_counter_nonnegative_check CHECK (
    last_totp_counter IS NULL OR last_totp_counter >= 0
  )
);

CREATE TABLE identity_api.user_mfa_recovery_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES identity_api.users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  consumed_at TIMESTAMPTZ,
  CONSTRAINT user_mfa_recovery_codes_user_hash_unique UNIQUE (user_id, code_hash)
);

CREATE INDEX user_mfa_recovery_codes_available_idx
  ON identity_api.user_mfa_recovery_codes (user_id, created_at)
  WHERE consumed_at IS NULL;
