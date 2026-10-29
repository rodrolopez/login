CREATE TABLE identity_api.account_action_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  email_id UUID NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose IN ('email_verification', 'password_recovery')),
  token_hash CHAR(64) NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT account_action_tokens_email_owner_fk
    FOREIGN KEY (email_id, user_id)
    REFERENCES identity_api.user_emails (id, user_id)
    ON DELETE CASCADE,
  CONSTRAINT account_action_tokens_expiry_check CHECK (expires_at > created_at),
  CONSTRAINT account_action_tokens_consumed_check CHECK (
    consumed_at IS NULL OR consumed_at >= created_at
  )
);

CREATE INDEX account_action_tokens_user_purpose_expiry_idx
  ON identity_api.account_action_tokens (user_id, purpose, expires_at DESC);

CREATE INDEX account_action_tokens_expiry_idx
  ON identity_api.account_action_tokens (expires_at)
  WHERE consumed_at IS NULL;
