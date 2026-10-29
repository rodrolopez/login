ALTER TABLE identity_api.password_credentials
  DROP CONSTRAINT password_credentials_password_hash_check;

ALTER TABLE identity_api.password_credentials
  ADD CONSTRAINT password_credentials_password_hash_check CHECK (
    password_hash ~ '^\$argon2id\$v=19\$m=[0-9]+,(p=[0-9]+,t=[0-9]+|t=[0-9]+,p=[0-9]+)\$[A-Za-z0-9+/]{8,}={0,2}\$[A-Za-z0-9+/]{16,}={0,2}$'
  );
