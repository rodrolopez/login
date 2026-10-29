import 'dotenv/config';
import { readPostgresConfig } from '../infrastructure/config.js';
import { createPostgresPool } from '../infrastructure/postgres/pool.js';
import { runMigrations } from '../infrastructure/postgres/migrations.js';

async function main(): Promise<void> {
  let pool: ReturnType<typeof createPostgresPool> | undefined;

  try {
    const config = readPostgresConfig();
    pool = createPostgresPool(config);
    const result = await runMigrations(pool);
    process.stdout.write(
      `Migrations complete: ${result.applied.length} applied, ${result.alreadyApplied} already current.\n`,
    );
  } catch {
    process.stderr.write(
      'Migration command failed. No migration runs automatically at application startup. Check configuration and database availability.\n',
    );
    process.exitCode = 1;
  } finally {
    await pool?.end();
  }
}

void main();
