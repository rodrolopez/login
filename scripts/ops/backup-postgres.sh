#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
PRODUCTION_ENV_FILE="${PRODUCTION_ENV_FILE:?Set PRODUCTION_ENV_FILE to the protected production env file}"
BACKUP_DIR="${BACKUP_DIR:-$ROOT_DIR/backups}"
BACKUP_DATABASE="${BACKUP_DATABASE:-identity_api}"

if [[ ! -f "$PRODUCTION_ENV_FILE" ]]; then
  printf 'Production environment file not found.\n' >&2
  exit 1
fi
if [[ ! "$BACKUP_DATABASE" =~ ^[a-z][a-z0-9_]{0,62}$ ]]; then
  printf 'Invalid database name.\n' >&2
  exit 1
fi

mkdir -p -- "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_file="$BACKUP_DIR/${BACKUP_DATABASE}-${timestamp}.dump"
compose=(docker compose --env-file "$PRODUCTION_ENV_FILE" -f "$ROOT_DIR/docker-compose.prod.yml")

if [[ -e "$backup_file" ]]; then
  printf 'Backup file already exists; refusing to overwrite it.\n' >&2
  exit 1
fi

temporary_file="$(mktemp "$BACKUP_DIR/.${BACKUP_DATABASE}-${timestamp}.XXXXXX")"
trap 'rm -f -- "$temporary_file"' EXIT
"${compose[@]}" exec -T postgres sh -ec \
  'export PGPASSWORD="$POSTGRES_PASSWORD"; exec pg_dump --host=127.0.0.1 --username="$POSTGRES_USER" --dbname="$1" --format=custom --no-owner --no-acl' \
  sh "$BACKUP_DATABASE" > "$temporary_file"
test -s "$temporary_file"
mv -- "$temporary_file" "$backup_file"
trap - EXIT
chmod 600 "$backup_file"
printf 'Backup created: %s\n' "$backup_file"
