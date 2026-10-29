\set ON_ERROR_STOP on

\getenv runtime_password IDENTITY_APP_PASSWORD
\getenv migration_password IDENTITY_MIGRATOR_PASSWORD
SELECT (length(:'runtime_password') >= 32 AND length(:'migration_password') >= 32) AS secrets_valid \gset
\if :secrets_valid
\else
\echo 'Runtime and migration passwords must each contain at least 32 characters.'
\quit
\endif

CREATE ROLE identity_migrator LOGIN PASSWORD :'migration_password';
CREATE ROLE identity_app LOGIN PASSWORD :'runtime_password';
CREATE DATABASE identity_api OWNER identity_migrator;
GRANT CONNECT ON DATABASE identity_api TO identity_app;

\connect identity_api

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO identity_migrator;
CREATE SCHEMA identity_api AUTHORIZATION identity_migrator;
GRANT USAGE ON SCHEMA identity_api TO identity_app;
ALTER DEFAULT PRIVILEGES FOR ROLE identity_migrator IN SCHEMA identity_api
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO identity_app;
ALTER DEFAULT PRIVILEGES FOR ROLE identity_migrator IN SCHEMA identity_api
  GRANT USAGE, SELECT ON SEQUENCES TO identity_app;
