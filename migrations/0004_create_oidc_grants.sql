CREATE TABLE identity_api.oidc_grants (
  grant_id TEXT PRIMARY KEY CHECK (char_length(grant_id) BETWEEN 1 AND 512),
  account_id UUID NOT NULL REFERENCES identity_api.users (id) ON DELETE CASCADE,
  client_id TEXT NOT NULL CHECK (char_length(client_id) BETWEEN 1 AND 512),
  payload JSONB NOT NULL,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX oidc_grants_account_client_idx
  ON identity_api.oidc_grants (account_id, client_id);
CREATE INDEX oidc_grants_expiration_idx
  ON identity_api.oidc_grants (expires_at)
  WHERE expires_at IS NOT NULL;
