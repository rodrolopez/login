import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import type { Pool } from 'pg';

const MIGRATION_NAME_PATTERN = /^(\d{4})_([a-z0-9_]+)\.sql$/;
const MIGRATION_ADVISORY_LOCK = 1_217_842_256;

interface MigrationFile {
  version: string;
  name: string;
  path: string;
}

interface AppliedMigration {
  version: string;
  checksum: string;
}

export interface MigrationResult {
  applied: string[];
  alreadyApplied: number;
}

async function findMigrationFiles(directory: string): Promise<MigrationFile[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const files: MigrationFile[] = [];

  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith('.sql')) {
      continue;
    }

    const match = MIGRATION_NAME_PATTERN.exec(entry.name);
    if (!match) {
      throw new Error(`Invalid migration filename: ${entry.name}`);
    }

    files.push({
      version: match[1]!,
      name: match[2]!,
      path: join(directory, entry.name),
    });
  }

  files.sort((left, right) => left.version.localeCompare(right.version));
  for (let index = 1; index < files.length; index += 1) {
    if (files[index - 1]?.version === files[index]?.version) {
      throw new Error(`Duplicate migration version: ${files[index]?.version}`);
    }
  }

  return files;
}

export async function runMigrations(
  pool: Pool,
  directory = join(process.cwd(), 'migrations'),
): Promise<MigrationResult> {
  const client = await pool.connect();
  let lockAcquired = false;

  try {
    await client.query('SELECT pg_advisory_lock($1)', [MIGRATION_ADVISORY_LOCK]);
    lockAcquired = true;

    await client.query(`
      CREATE TABLE IF NOT EXISTS public.schema_migrations (
        version TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        checksum TEXT NOT NULL,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `);

    const migrationFiles = await findMigrationFiles(directory);
    const appliedRows = await client.query<AppliedMigration>(
      'SELECT version, checksum FROM public.schema_migrations ORDER BY version',
    );
    const appliedByVersion = new Map(
      appliedRows.rows.map((migration) => [migration.version, migration.checksum]),
    );
    const fileVersions = new Set(migrationFiles.map((migration) => migration.version));

    for (const version of appliedByVersion.keys()) {
      if (!fileVersions.has(version)) {
        throw new Error(`Applied migration file is missing: ${version}`);
      }
    }

    const pending: Array<MigrationFile & { sql: string; checksum: string }> = [];
    for (const migration of migrationFiles) {
      const sql = await readFile(migration.path, 'utf8');
      const checksum = createHash('sha256').update(sql).digest('hex');
      const priorChecksum = appliedByVersion.get(migration.version);

      if (priorChecksum && priorChecksum !== checksum) {
        throw new Error(`Applied migration was modified: ${migration.version}`);
      }

      if (!priorChecksum) {
        pending.push({ ...migration, sql, checksum });
      }
    }

    const applied: string[] = [];
    for (const migration of pending) {
      await client.query('BEGIN');
      try {
        await client.query(migration.sql);
        await client.query(
          `INSERT INTO public.schema_migrations (version, name, checksum)
           VALUES ($1, $2, $3)`,
          [migration.version, migration.name, migration.checksum],
        );
        await client.query('COMMIT');
        applied.push(migration.version);
      } catch (error) {
        try {
          await client.query('ROLLBACK');
        } catch {
          // The original migration failure is more useful to the caller.
        }
        throw error;
      }
    }

    return { applied, alreadyApplied: migrationFiles.length - pending.length };
  } finally {
    if (lockAcquired) {
      try {
        await client.query('SELECT pg_advisory_unlock($1)', [MIGRATION_ADVISORY_LOCK]);
      } catch {
        // A closed connection releases its session-level advisory lock.
      }
    }

    client.release();
  }
}
