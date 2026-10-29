CREATE TABLE identity_api.users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_status TEXT NOT NULL DEFAULT 'pending'
    CHECK (account_status IN ('pending', 'active', 'suspended', 'disabled', 'anonymized')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  disabled_at TIMESTAMPTZ,
  anonymized_at TIMESTAMPTZ,
  CONSTRAINT users_disabled_timestamp_check CHECK (
    (account_status = 'disabled' AND disabled_at IS NOT NULL)
    OR (account_status <> 'disabled' AND disabled_at IS NULL)
  ),
  CONSTRAINT users_anonymized_timestamp_check CHECK (
    (account_status = 'anonymized' AND anonymized_at IS NOT NULL)
    OR (account_status <> 'anonymized' AND anonymized_at IS NULL)
  )
);

CREATE INDEX users_account_status_created_at_idx
  ON identity_api.users (account_status, created_at);

CREATE TABLE identity_api.user_emails (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES identity_api.users (id) ON DELETE CASCADE,
  email TEXT NOT NULL CHECK (char_length(email) BETWEEN 3 AND 320),
  verified_at TIMESTAMPTZ,
  is_primary BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT user_emails_id_user_unique UNIQUE (id, user_id)
);

CREATE UNIQUE INDEX user_emails_case_insensitive_unique
  ON identity_api.user_emails (lower(email));
CREATE UNIQUE INDEX user_emails_one_primary_per_user
  ON identity_api.user_emails (user_id)
  WHERE is_primary;
CREATE INDEX user_emails_user_id_idx ON identity_api.user_emails (user_id);

CREATE TABLE identity_api.password_credentials (
  user_id UUID PRIMARY KEY REFERENCES identity_api.users (id) ON DELETE CASCADE,
  password_hash TEXT NOT NULL CHECK (
    password_hash ~ '^\$argon2id\$v=19\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]{8,}={0,2}\$[A-Za-z0-9+/]{16,}={0,2}$'
  ),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE identity_api.external_identities (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES identity_api.users (id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider ~ '^[a-z][a-z0-9_-]{1,63}$'),
  issuer TEXT NOT NULL CHECK (char_length(issuer) BETWEEN 1 AND 512),
  subject TEXT NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 512),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT external_identities_issuer_subject_unique UNIQUE (issuer, subject),
  CONSTRAINT external_identities_user_provider_unique UNIQUE (user_id, provider)
);

CREATE INDEX external_identities_user_id_idx
  ON identity_api.external_identities (user_id);
