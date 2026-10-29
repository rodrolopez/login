#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
PRODUCTION_ENV_FILE="${PRODUCTION_ENV_FILE:?Set PRODUCTION_ENV_FILE to the protected production env file}"
BACKUP_FILE="${1:?Usage: restore-postgres.sh /path/to/backup.dump}"
RESTORE_DATABASE="${RESTORE_DATABASE:?Set a new, empty recovery database name ending in _restore}"
IDENTITY_MIGRATOR_PASSWORD="${IDENTITY_MIGRATOR_PASSWORD:?Load the migration role password from the secret manager}"

if [[ ! -f "$PRODUCTION_ENV_FILE" || ! -f "$BACKUP_FILE" ]]; then
  printf 'Environment file or backup file not found.\n' >&2
  exit 1
fi
if [[ ! "$RESTORE_DATABASE" =~ ^[a-z][a-z0-9_]{0,54}_restore$ ]]; then
  printf 'Recovery database must be a valid name ending in _restore.\n' >&2
  exit 1
fi

compose=(docker compose --env-file "$PRODUCTION_ENV_FILE" -f "$ROOT_DIR/docker-compose.prod.yml")
"${compose[@]}" exec -T -e IDENTITY_MIGRATOR_PASSWORD postgres sh -ec \
  'export PGPASSWORD="$POSTGRES_PASSWORD"; exec createdb --host=127.0.0.1 --username="$POSTGRES_USER" --owner=identity_migrator "$1"' \
  sh "$RESTORE_DATABASE"

if ! "${compose[@]}" exec -T -e IDENTITY_MIGRATOR_PASSWORD postgres sh -ec \
  'export PGPASSWORD="$IDENTITY_MIGRATOR_PASSWORD"; exec pg_restore --host=127.0.0.1 --username=identity_migrator --dbname="$1" --format=custom --no-owner --no-acl --exit-on-error' \
  sh "$RESTORE_DATABASE" < "$BACKUP_FILE"; then
  printf 'Restore failed. The newly created recovery database was retained for investigation: %s\n' \
    "$RESTORE_DATABASE" >&2
  exit 1
fi

printf 'Restore completed to the new database: %s\n' "$RESTORE_DATABASE"
printf 'Validate it and perform a controlled cutover; the active database was not modified.\n'
