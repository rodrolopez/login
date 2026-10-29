import 'dotenv/config';
import { startTelemetry } from './infrastructure/telemetry.js';

async function startServer(): Promise<void> {
  let pool: import('pg').Pool | undefined;
  let redis: import('ioredis').Redis | undefined;
  let server: import('node:http').Server | undefined;
  let shutdownTelemetry: () => Promise<void> = async () => undefined;

  try {
    shutdownTelemetry = await startTelemetry();

    const [
      appModule,
      configModule,
      connectModule,
      poolModule,
      redisModule,
      oidcModule,
      googleModule,
    ] = await Promise.all([
      import('./app.js'),
      import('./infrastructure/config.js'),
      import('./infrastructure/connect.js'),
      import('./infrastructure/postgres/pool.js'),
      import('./infrastructure/redis/client.js'),
      import('./oidc/provider.js'),
      import('./auth/google-oidc-client.js'),
    ]);

    const config = configModule.readInfrastructureConfig();
    pool = poolModule.createPostgresPool(config.postgres);
    redis = redisModule.createRedisClient(config.redis);
    await connectModule.connectInfrastructure(pool, redis);
    const oidc = oidcModule.createOidcProviderFromEnvironment(pool, redis);
    const googleOidcClient = config.google
      ? new googleModule.OpenIdGoogleClient(config.google)
      : undefined;

    server = appModule
      .createApp({
        pool,
        redis,
        rateLimitKeySecret: config.redis.password,
        ...(config.mfaEncryptionKey ? { mfaEncryptionKey: config.mfaEncryptionKey } : {}),
        corsAllowedOrigins: config.corsAllowedOrigins,
        oidcProvider: oidc.provider,
        ...(googleOidcClient && config.google
          ? { googleOidcClient, googleRedirectUri: config.google.redirectUri }
          : {}),
      })
      .listen(config.port, '0.0.0.0', () => {
        process.stdout.write(`Identity API listening on port ${config.port}\n`);
      });

    let shuttingDown = false;
    const shutdown = async (signal: NodeJS.Signals): Promise<void> => {
      if (shuttingDown) return;
      shuttingDown = true;
      process.stdout.write(`Received ${signal}; closing infrastructure connections\n`);

      const httpClosed = new Promise<void>((resolve) => {
        if (!server) return resolve();
        const forceCloseTimer = setTimeout(() => server?.closeAllConnections(), 5_000);
        forceCloseTimer.unref();
        server.close(() => {
          clearTimeout(forceCloseTimer);
          resolve();
        });
        server.closeIdleConnections();
      });

      await httpClosed;
      const results = await Promise.allSettled([pool?.end(), redis?.quit(), shutdownTelemetry()]);
      if (results.some((result) => result.status === 'rejected')) {
        process.stderr.write('One or more infrastructure connections did not close cleanly\n');
        process.exitCode = 1;
      }
    };

    process.once('SIGINT', shutdown);
    process.once('SIGTERM', shutdown);
  } catch {
    process.stderr.write(
      'Identity API startup failed while validating infrastructure or configuration. Check local service status and required environment variables.\n',
    );
    await Promise.allSettled([pool?.end(), shutdownTelemetry()]);
    redis?.disconnect();
    process.exitCode = 1;
  }
}

void startServer();
